/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

#include <algorithm>

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_store/buffered_chunk_store.h"
#include "maidsafe/private/chunk_store/chunk_manager.h"
#include "maidsafe/private/chunk_store/local_chunk_manager.h"
#include "maidsafe/private/return_codes.h"


namespace maidsafe {

namespace priv {

namespace chunk_store {

namespace {

// Default maximum number of operations to be processed in parallel.
const int kMaxActiveOps(4);
// Time to wait in WaitForCompletion before failing.
const std::chrono::duration<int> kCompletionWaitTimeout(std::chrono::minutes(3));
// Time to wait in WaitForConflictingOps before failing.
const std::chrono::duration<int> kOperationWaitTimeout(std::chrono::seconds(150));  // 2.5 mins
// Time period in which not to retry a previously failed get operation.
const std::chrono::duration<int> kGetRetryTimeout(std::chrono::seconds(3));

template <typename Elem, typename Traits>
std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& ostream,
                                             const RemoteChunkStore::OpType &op_type) {
  std::string op_str;
  switch (op_type) {
    case RemoteChunkStore::OpType::kGet:
      op_str = "get";
      break;
    case RemoteChunkStore::OpType::kGetLock:
      op_str = "get and lock";
      break;
    case RemoteChunkStore::OpType::kStore:
      op_str = "store";
      break;
    case RemoteChunkStore::OpType::kModify:
      op_str = "modify";
      break;
    case RemoteChunkStore::OpType::kDelete:
      op_str = "delete";
      break;
    default:
      op_str = "[invalid OpType]";
      break;
  }

  for (std::string::iterator itr(op_str.begin()); itr != op_str.end(); ++itr)
    ostream << ostream.widen(*itr);
  return ostream;
}

}  // unnamed namespace

RemoteChunkStore::RemoteChunkStore(
    std::shared_ptr<BufferedChunkStore> chunk_store,
    std::shared_ptr<ChunkManager> chunk_manager,
    std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority)
        : sig_num_pending_ops_(new NumPendingOpsSig),
          chunk_store_(chunk_store),
          chunk_manager_(chunk_manager),
          chunk_action_authority_(chunk_action_authority),
          chunk_manager_get_connection_(),
          chunk_manager_store_connection_(),
          chunk_manager_modify_connection_(),
          chunk_manager_delete_connection_(),
          mutex_(),
          cond_var_(),
          max_active_ops_(kMaxActiveOps),
          active_ops_count_(0),
          completion_wait_timeout_(kCompletionWaitTimeout),
          operation_wait_timeout_(kOperationWaitTimeout),
          pending_ops_(),
          failed_ops_(),
          waiting_gets_(),
          not_modified_gets_(),
          failed_gets_(),
          op_count_(),
          op_success_count_(),
          op_skip_count_(),
          op_size_() {
  chunk_manager_get_connection_ = chunk_manager_->sig_chunk_got()->connect(boost::bind(
      &RemoteChunkStore::OnOpResult, this, OpType::kGet, _1, _2));
  chunk_manager_store_connection_ = chunk_manager_->sig_chunk_stored()->connect(boost::bind(
      &RemoteChunkStore::OnOpResult, this, OpType::kStore, _1, _2));
  chunk_manager_modify_connection_ = chunk_manager_->sig_chunk_modified()->connect(boost::bind(
      &RemoteChunkStore::OnOpResult, this, OpType::kModify, _1, _2));
  chunk_manager_delete_connection_ = chunk_manager_->sig_chunk_deleted()->connect(boost::bind(
      &RemoteChunkStore::OnOpResult, this, OpType::kDelete, _1, _2));
}

RemoteChunkStore::~RemoteChunkStore() {
  chunk_manager_get_connection_.disconnect();
  chunk_manager_store_connection_.disconnect();
  chunk_manager_modify_connection_.disconnect();
  chunk_manager_delete_connection_.disconnect();
  std::lock_guard<std::mutex> lock(mutex_);
  active_ops_count_ = 0;
  pending_ops_.clear();
  failed_ops_.clear();
}

std::string RemoteChunkStore::Get(const ChunkId& name, const asymm::Keys& keys) {
  LOG(kInfo) << "Get - " << Base32Substr(name);
  std::unique_lock<std::mutex> lock(mutex_);
  if (!chunk_action_authority_->ValidName(name)) {
    LOG(kError) << "Get - Invalid chunk name " << Base32Substr(name);
    return "";
  }

  if (chunk_action_authority_->Cacheable(name) && pending_ops_.left.count(name.string()) == 0) {
    std::string content(chunk_store_->Get(name));
    if (!content.empty()) {
      LOG(kInfo) << "Get - Found local content for " << Base32Substr(name);
      return content;
    }
  }

  uint32_t id(EnqueueOp(name, OperationData(OpType::kGet, nullptr, keys, true), lock));
  ProcessPendingOps(lock);
  if (!WaitForGetOps(name, id, lock)) {
    LOG(kError) << "Get - Timed out for " << Base32Substr(name) << " - ID " << id;
    return "";
  }

  std::string content(chunk_store_->Get(name));
  if (content.empty()) {
    LOG(kError) << "Get - Failed retrieving " << Base32Substr(name) << " - ID " << id;
    return "";
  }

  // check if there is a get op for this chunk following
  auto it = pending_ops_.begin();
  while (it != pending_ops_.end()) {
    if (it->left == name.string()) {
      if (it->info.op_type == OpType::kGet) {
//         pending_ops_.erase(it);  // trigger next one
//         cond_var_.notify_all();
      } else {
        it = pending_ops_.end();
      }
      break;
    }
    ++it;
  }

  {
    auto waiting_it = waiting_gets_.find(name);
    if (waiting_it != waiting_gets_.end())
      waiting_gets_.erase(waiting_it);
  }

  if (it == pending_ops_.end() && waiting_gets_.find(name) == waiting_gets_.end()) {
    LOG(kInfo) << "Get - Done, deleting " << Base32Substr(name) << " - ID " << id;
    if (chunk_action_authority_->Cacheable(name))
      chunk_store_->MarkForDeletion(name);
    else
      chunk_store_->Delete(name);
  }

  ProcessPendingOps(lock);

  return content;
}

int RemoteChunkStore::GetAndLock(const ChunkId& name,
                                 const ChunkVersion& local_version,
                                 const asymm::Keys& keys,
                                 std::string* content) {
  LOG(kInfo) << "GetAndLock - " << Base32Substr(name);
  if (!content) {
    LOG(kError) << "GetAndLock - NULL pointer passed for content";
    return kGeneralError;
  }
  std::unique_lock<std::mutex> lock(mutex_);
  if (!chunk_action_authority_->ValidName(name)) {
    LOG(kError) << "GetAndLock - Invalid chunk name " << Base32Substr(name);
    return kGeneralError;
  }

  if (chunk_action_authority_->Cacheable(name) && pending_ops_.left.count(name.string()) == 0) {
    std::string local_content(chunk_store_->Get(name));
    if (!local_content.empty()) {
      LOG(kInfo) << "GetAndLock - Found local content for "
                 << Base32Substr(name);
      *content = local_content;
      return kSuccess;
    }
  }
  OperationData op_data(OpType::kGetLock, nullptr, keys, true);
  op_data.local_version = local_version;
    uint32_t id(EnqueueOp(name, op_data, lock));
  ProcessPendingOps(lock);
  if (!WaitForGetOps(name, id, lock)) {
    LOG(kError) << "GetAndLock - Timed out for " << Base32Substr(name) << " - ID " << id;
    return kGeneralError;
  }

  std::string local_content(chunk_store_->Get(name));
  bool chunk_not_modified(false);
  auto not_modified_it(not_modified_gets_.find(name));
  if (not_modified_it != not_modified_gets_.end()) {
    not_modified_gets_.erase(not_modified_it);
    chunk_not_modified = true;
  }
  if (local_content.empty() && !chunk_not_modified) {
    LOG(kError) << "GetAndLock - Failed retrieving " << Base32Substr(name) << " - ID " << id;
    return kGeneralError;
  }

  auto waiting_it = waiting_gets_.find(name);
  if (waiting_it != waiting_gets_.end())
    waiting_gets_.erase(waiting_it);

  if (waiting_gets_.find(name) == waiting_gets_.end()) {
    LOG(kInfo) << "GetAndLock - Done, deleting " << Base32Substr(name)
               << " - ID " << id;
    if (chunk_action_authority_->Cacheable(name))
      chunk_store_->MarkForDeletion(name);
    else
      chunk_store_->Delete(name);
  }

  ProcessPendingOps(lock);
  *content = local_content;
  if (chunk_not_modified)
    return kChunkNotModified;

  return kSuccess;
}

bool RemoteChunkStore::Store(const ChunkId& name,
                             const std::string& content,
                             const OpFunctor& callback,
                             const asymm::Keys keys) {
  LOG(kInfo) << "Store - " << Base32Substr(name);

  std::unique_lock<std::mutex> lock(mutex_);
  uint32_t id(EnqueueOp(name, OperationData(OpType::kStore, callback, keys, false), lock));
  WaitResult result(WaitForConflictingOps(name, OpType::kStore, id, lock));
  if (result != WaitResult::kSuccess) {
    LOG(kWarning) << "Store - Terminated early for " << Base32Substr(name);
    return result == WaitResult::kCancelled;
  }
  if (!chunk_action_authority_->Store(name, content, keys.public_key)) {
    LOG(kError) << "Store - Could not store " << Base32Substr(name) << " locally.";
    pending_ops_.right.erase(id);
    cond_var_.notify_all();
    return false;
  }

  // operation can now be processed
  auto it = pending_ops_.right.find(id);
  if (it != pending_ops_.right.end())
    it->info.ready = true;

  ProcessPendingOps(lock);
  return true;
}

bool RemoteChunkStore::Delete(const ChunkId& name,
                              const OpFunctor& callback,
                              const asymm::Keys keys) {
  LOG(kInfo) << "Delete - " << Base32Substr(name);

  std::unique_lock<std::mutex> lock(mutex_);
  uint32_t id(EnqueueOp(name, OperationData(OpType::kDelete, callback, keys, false), lock));
  WaitResult result(WaitForConflictingOps(name, OpType::kDelete, id, lock));
  if (result != WaitResult::kSuccess) {
    LOG(kWarning) << "Delete - Terminated early for " << Base32Substr(name);
    return result == WaitResult::kCancelled;
  }
  asymm::PlainText data(RandomString(16));
  asymm::Signature signature(asymm::Sign(data, keys.private_key));
  chunk_actions::SignedData proof;
  proof.set_data(data.string());
  proof.set_signature(signature.string());
  if (!chunk_action_authority_->Delete(name, proof.SerializeAsString(), keys.public_key)) {
    LOG(kError) << "Delete - Could not delete " << Base32Substr(name) << " locally.";
    pending_ops_.right.erase(id);
    cond_var_.notify_all();
    return false;
  }

  // operation can now be processed
  auto it = pending_ops_.right.find(id);
  if (it != pending_ops_.right.end())
    it->info.ready = true;

  ProcessPendingOps(lock);
  return true;
}

bool RemoteChunkStore::Modify(const ChunkId& name,
                              const std::string& content,
                              const OpFunctor& callback,
                              const asymm::Keys keys) {
  LOG(kInfo) << "Modify - " << Base32Substr(name);

  if (!chunk_action_authority_->Modifiable(name)) {
    LOG(kError) << "Modify - Type of chunk " << Base32Substr(name) << " not supported.";
    return false;
  }

  std::unique_lock<std::mutex> lock(mutex_);
  OperationData op_data(OpType::kModify, callback, keys, true);
  op_data.content = content;
  EnqueueOp(name, op_data, lock);
//   uint32_t id(EnqueueOp(name, op_data, &lock));
//   int result(WaitForConflictingOps(name, kOpModify, id, &lock));
//   if (result != kWaitSuccess) {
//     LOG(kWarning) << "Modify - Terminated early for " << Base32Substr(name);
//     return result == kWaitCancelled;
//   }

  ProcessPendingOps(lock);
  return true;
}

bool RemoteChunkStore::WaitForCompletion() {
  std::unique_lock<std::mutex> lock(mutex_);
  while (!pending_ops_.empty()) {
    LOG(kInfo) << "WaitForCompletion - " << pending_ops_.size() << " pending operations, "
               << active_ops_count_ << " of them active...";
    (*sig_num_pending_ops_)(pending_ops_.size());
    if (!cond_var_.wait_for(lock, completion_wait_timeout_)) {
      LOG(kError) << "WaitForCompletion - Timed out with " << pending_ops_.size()
                  << " pending operations, " << active_ops_count_ << " of them active.";
      return false;
    }
  }
  LOG(kInfo) << "WaitForCompletion - Done.";
  return true;
}

void RemoteChunkStore::LogStats() {
  std::lock_guard<std::mutex> lock(mutex_);
  OpType op = OpType::kGet;
  while (op <= OpType::kDelete) {
    int i(static_cast<int>(op));
    LOG(kInfo) << "LogStats() - Could " << op << " " << op_success_count_[i] << " and skip "
               << op_skip_count_[i] << " of " << op_count_[i] << " chunks ("
               << BytesToBinarySiUnits(op_size_[i]) << ").";
    op = static_cast<OpType>(i + 1);
  }

  std::ostringstream oss;
  for (auto it = pending_ops_.begin(); it != pending_ops_.end(); ++it) {
    oss << "\n\t" << Base32Substr(it->left) << " (" << it->info.op_type
        << (it->info.active ? ", active" : "") << ")";
  }
  if (!pending_ops_.empty()) {
    LOG(kWarning) << "LogStats() - " << pending_ops_.size() << " pending operations, "
                  << active_ops_count_ << " active :" << oss.str();
  }

  oss.str("");
  for (auto it = failed_ops_.begin(); it != failed_ops_.end(); ++it)
    oss << "\n\t" << Base32Substr(it->first) << " (" << it->second << ")";
  if (!failed_ops_.empty())
    LOG(kWarning) << "LogStats() - " << failed_ops_.size() << " failed operations:" << oss.str();
}

bool RemoteChunkStore::Empty() const {
  return chunk_store_->Empty();
}

void RemoteChunkStore::Clear() {
  chunk_store_->Clear();
}

void RemoteChunkStore::OnOpResult(const OpType& op_type, const ChunkId& name, const int& result) {
  std::unique_lock<std::mutex> lock(mutex_);

  // find first matching and active op
  auto it = pending_ops_.begin();
  for (; it != pending_ops_.end(); ++it) {
    if (it->left == name.string() &&
        (it->info.op_type == op_type ||
            (it->info.op_type == OpType::kGetLock && op_type == OpType::kGet)) && it->info.active) {
      break;
    }
  }
  if (it == pending_ops_.end()) {
    LOG(kWarning) << "OnOpResult - Unrecognised result for op '" << op_type << "' and chunk "
                  << Base32Substr(name) << " received. (" << result << ")";
//    if (it == pending_ops_.end())
//      LOG(kWarning) << "it == pending_ops_.end()";
//    if (it->info.op_type != op_type)
//      LOG(kWarning) << "it->info.op_type != op_type";
//    if (!it->info.active)
//      LOG(kWarning) << "!it->info.active";
    return;
  }

//  LOG(kInfo) << "OnOpResult - Got result for op '" << op_type << "' and chunk "
//             << Base32Substr(name) << " - ID " << it->right;

  // statistics
  if (result == kSuccess) {
    ++op_success_count_[static_cast<int>(op_type)];
    switch (op_type) {
      case OpType::kGet:
      case OpType::kStore:
        op_size_[static_cast<int>(op_type)] += chunk_store_->Size(name);
        break;
      case OpType::kModify:
        op_size_[static_cast<int>(op_type)] += it->info.content.size();
        break;
      default:
        break;
    }
    failed_gets_.erase(name);  // [sic] any successful op, not just get
    if (op_type == OpType::kGet)
      waiting_gets_.insert(name);
  } else if (result == kChunkNotModified) {
    LOG(kInfo) << "OnOpResult -GetAndLock done, local version of " << Base32Substr(name)
               << "is up to date";
    not_modified_gets_.insert(name);
  } else {
    LOG(kError) << "OnOpResult - Failed to " << op_type << " " << Base32Substr(name) << " ("
                << result << ")";
    if (op_type == OpType::kGet)
      failed_gets_[name] = std::chrono::system_clock::now();
    failed_ops_.insert(std::make_pair(name, op_type));
  }

  if (op_type == OpType::kStore) {
    // don't keep non-cacheable chunks locally
    LOG(kInfo) << "OnOpResult - Store done, deleting " << Base32Substr(name);
    if (chunk_action_authority_->Cacheable(name))
      chunk_store_->MarkForDeletion(name);
    else
      chunk_store_->Delete(name);
    // NOTE cacheable chunks that failed to store will remain locally
  }

  OpFunctor callback(it->info.callback);
  --active_ops_count_;
//   LOG(kInfo) << "OnOpResult - Erasing completed op '" << kOpName[op_type]
//              << "' for chunk " << Base32Substr(name) << " - ID "
//              << it->right;
  pending_ops_.erase(it);
  cond_var_.notify_all();

  if (callback) {
    lock.unlock();
    callback(result == kSuccess);
    lock.lock();
  }

  if (op_type != OpType::kGet)
    ProcessPendingOps(lock);
}

RemoteChunkStore::WaitResult RemoteChunkStore::WaitForConflictingOps(
    const ChunkId& name,
    const OpType& op_type,
    const uint32_t& transaction_id,
    std::unique_lock<std::mutex>& lock) {
  if (transaction_id == 0)  // our op is redundant
    return WaitResult::kCancelled;

  // wait until our operation is the next one, or has been cancelled

  for (;;) {
    // does our op still exist?
    if (pending_ops_.right.find(transaction_id) == pending_ops_.right.end()) {
      LOG(kWarning) << "WaitForConflictingOps - Operation to " << op_type << " "
                    << Base32Substr(name) << " with transaction ID " << transaction_id
                    << " was cancelled.";
      return WaitResult::kCancelled;
    }

    // is our op the next one with this name?
    auto it = pending_ops_.left.find(name.string());
    if (it != pending_ops_.left.end() && pending_ops_.project_right(it)->first == transaction_id)
      return WaitResult::kSuccess;

    if (!cond_var_.wait_for(lock, operation_wait_timeout_)) {
      LOG(kError) << "WaitForConflictingOps - Timed out trying to " << op_type << " "
                  << Base32Substr(name) << " with " << pending_ops_.left.count(name.string())
                  << " pending operations. - ID " << transaction_id;
      pending_ops_.right.erase(transaction_id);
      cond_var_.notify_all();
      failed_ops_.insert(std::make_pair(name, op_type));
      return WaitResult::kTimeout;
    }
  }
}

bool RemoteChunkStore::WaitForGetOps(const ChunkId& name,
                                     const uint32_t& transaction_id,
                                     std::unique_lock<std::mutex>& lock) {
  while (pending_ops_.right.find(transaction_id) != pending_ops_.right.end()) {
    if (!cond_var_.wait_for(lock, operation_wait_timeout_)) {
      LOG(kError) << "WaitForGetOps - Timed out for " << Base32Substr(name) << " with "
                  << pending_ops_.left.count(name.string()) << " pending operations.  ID "
                  << transaction_id;
      pending_ops_.right.erase(transaction_id);
      cond_var_.notify_all();
      // failed_ops_.insert(std::make_pair(name, kOpGet));
      return false;
    }
  }
  return true;
}

uint32_t RemoteChunkStore::EnqueueOp(const ChunkId& name,
                                     const OperationData& op_data,
                                     std::unique_lock<std::mutex>& lock) {
  ++op_count_[static_cast<int>(op_data.op_type)];

  // Are we able to cancel a previous op for this chunk?
  auto it = pending_ops_.left.upper_bound(name.string());
  if (pending_ops_.left.lower_bound(name.string()) != it) {
    --it;
//     LOG(kInfo) << "EnqueueOp - Op '" << op_data.op_type << "', found prev '" << it->info.op_type
//                << "', chunk " << Base32Substr(name) << ", "
//                << (it->info.active ? "active" : "inactive");
    if (!it->info.active) {
      bool cancel_prev(false), cancel_curr(false);
      if (op_data.op_type == OpType::kModify &&
          it->info.op_type == OpType::kModify &&
          chunk_action_authority_->ModifyReplaces(name)) {
        cancel_prev = true;
      } else if (op_data.op_type == OpType::kDelete &&
                 (it->info.op_type == OpType::kModify ||
                  it->info.op_type == OpType::kStore)) {
        // NOTE has potential side effects (multiple stores, unauth. delete)
        cancel_prev = true;
        cancel_curr= true;
      }

      if (cancel_prev) {
        LOG(kInfo) << "EnqueueOp - Cancel previous '" << it->info.op_type << "' due to '"
                   << op_data.op_type << "' for " << Base32Substr(name);
        OpFunctor callback(it->info.callback);
        OpType prev_op_type(it->info.op_type);
        ++op_skip_count_[static_cast<int>(prev_op_type)];
        pending_ops_.left.erase(it);
        cond_var_.notify_all();
        if (prev_op_type == OpType::kModify && callback) {
          // run callback, because Modify doesn't block
          lock.unlock();
          callback(true);
          lock.lock();
        }
      }
      if (cancel_curr) {
        ++op_skip_count_[static_cast<int>(op_data.op_type)];
        return 0;
      }
    }
  }

  uint32_t id;
  do {
    id = RandomUint32();
  } while (id == 0 || pending_ops_.right.find(id) != pending_ops_.right.end());
  pending_ops_.push_back(OperationBimap::value_type(name.string(), id, op_data));
//   LOG(kInfo) << "EnqueueOp - Enqueueing op '" << kOpName[op_data.op_type]
//              << "' for " << Base32Substr(name) << " with ID " << id;
  return id;
}

void RemoteChunkStore::ProcessPendingOps(std::unique_lock<std::mutex>& lock) {
//   LOG(kInfo) << "ProcessPendingOps - " << active_ops_count_ << " of max "
//              << max_active_ops_ << " ops active.";
  {
    // remove previously failed gets that can now be retried again
    auto now = std::chrono::system_clock::now();
    auto it = failed_gets_.begin();
    while (it != failed_gets_.end()) {
      if (it->second + kGetRetryTimeout < now)
        failed_gets_.erase(it++);
      else
        ++it;
    }
  }

  std::set<ChunkId> processed_gets;
  while (active_ops_count_ < max_active_ops_) {
    OperationData op_data;
    std::set<ChunkId> active_ops;
    auto it = pending_ops_.begin();  // always (re-)start from beginning!
    while (it != pending_ops_.end()) {
      if (it->info.active || !it->info.ready) {
        active_ops.insert(ChunkId(it->left));
      } else if (active_ops.find(ChunkId(it->left)) == active_ops.end() &&
                  ((it->info.op_type != OpType::kGet && it->info.op_type != OpType::kGetLock) ||
                  processed_gets.find(ChunkId(it->left)) == processed_gets.end())) {
        break;
      }
      ++it;
    }

    if (it == pending_ops_.end()) {
//         if (!pending_ops_.empty())
//           LOG(kInfo) << "ProcessPendingOps - " << pending_ops_.size()
//                      << " ops active or waiting for dependencies...";
      return;  // no op found that an currently be processed
    }

    ChunkId name(it->left);
    op_data = it->info;

    if (op_data.op_type == OpType::kGet || op_data.op_type == OpType::kGetLock) {
      if (chunk_store_->Has(name)) {
        LOG(kInfo) << "ProcessPendingOps - Already have chunk " << Base32Substr(name) << " - ID "
                   << it->right;
        waiting_gets_.insert(name);
        pending_ops_.erase(it);
        cond_var_.notify_all();
        return;
      } else if (failed_gets_.find(name) != failed_gets_.end()) {
        LOG(kWarning) << "ProcessPendingOps - Retrieving " << Base32Substr(name)
                      << " failed previously, not trying again. - ID " << it->right;
        pending_ops_.erase(it);
        cond_var_.notify_all();
        return;
      } else {
        processed_gets.insert(name);
      }
    }

//       LOG(kInfo) << "ProcessPendingOps - About to " << op_data.op_type
//                  << " chunk " << Base32Substr(name) << " - ID " << it->right;

    it->info.active = true;

    ++active_ops_count_;
    lock.unlock();
    switch (op_data.op_type) {
      case OpType::kGet:
        chunk_manager_->GetChunk(name, op_data.local_version, op_data.keys, false);
        break;
      case OpType::kGetLock:
        chunk_manager_->GetChunk(name, op_data.local_version, op_data.keys, true);
        break;
      case OpType::kStore:
        chunk_manager_->StoreChunk(name, op_data.keys);
        break;
      case OpType::kModify:
        chunk_manager_->ModifyChunk(name, op_data.content, op_data.keys);
        break;
      case OpType::kDelete:
        chunk_manager_->DeleteChunk(name, op_data.keys);
        break;
    }
    lock.lock();
  }
}

/*

void RemoteChunkStore::StoreOpBackups(
    std::shared_ptr<boost::asio::deadline_timer> timer,
    const std::string& pmid) {
  timer->expires_from_now(boost::posix_time::seconds(10));
  timer->async_wait(std::bind(
      &RemoteChunkStore::DoOpBackups, this, arg::_1, pmid, timer));
}

void RemoteChunkStore::DoOpBackups(
    boost::system::error_code error,
    const std::string& pmid,
    std::shared_ptr<boost::asio::deadline_timer> timer) {
  if (error)
    LOG(kError) << "Error " << error << " occurred.";
  std::stringstream op_stream(std::stringstream::in |
                              std::stringstream::out);
  int result = op_archiving::Serialize(*this, &op_stream);
  if (result != kSuccess)
    LOG(kError) << "Failed to serialize ops.";
  if (!chunk_store_->Delete("RemoteChunkStore" + pmid))
      LOG(kError) << "Failed to delete old ops.";
  if (!chunk_store_->Store("RemoteChunkStore" + pmid, op_stream.str()))
    LOG(kError) << "Failed to store ops.";
  // timer.reset();
  StoreOpBackups(timer, pmid);
}

template<class Archive>
void RemoteChunkStore::serialize(Archive& archive, const unsigned int) {  // NOLINT
  std::lock_guard<std::mutex> lock(mutex_);
  archive & active_mod_ops_;
  archive & pending_mod_ops_;
  archive & failed_hashable_ops_;
  archive & failed_non_hashable_store_ops_;
  std::list<std::string> removable_chunks(chunk_store_->GetRemovableChunks());
  archive & removable_chunks;
}

namespace op_archiving {

  int Serialize(const maidsafe::pd::RemoteChunkStore& remote_chunk_store,
                std::stringstream* output_stream) {
  if (!output_stream) {
    return -1;
  }
  try {
    boost::archive::text_oarchive oa(*output_stream);
    oa << remote_chunk_store;
  } catch(const std::exception& e) {
    LOG(kError) << e.what();
    return -1;
  }
  return kSuccess;
}

int Deserialize(std::stringstream* input_stream,
                maidsafe::pd::RemoteChunkStore& remote_chunk_store) {
  if (!input_stream)
    return -1;
  try {
    boost::archive::text_iarchive ia(*input_stream);
    ia >> remote_chunk_store;
  } catch(const std::exception& e) {
    LOG(kError) << e.what();
    return -1;
  }
  return kSuccess;
}

}  // namespace op_archiving

*/

std::shared_ptr<RemoteChunkStore> CreateLocalChunkStore(const fs::path& buffered_chunk_store_path,
                                                        const fs::path& local_chunk_manager_path,
                                                        const fs::path& chunk_lock_path,
                                                        boost::asio::io_service& asio_service,  // NOLINT (Dan)
                                                        const bptime::time_duration& delay) {
  std::shared_ptr<BufferedChunkStore> buffered_chunk_store(
      new BufferedChunkStore(asio_service));
  if (!buffered_chunk_store->Init(buffered_chunk_store_path)) {
    LOG(kError) << "Failed to initialise buffered chunk store.";
    return std::shared_ptr<RemoteChunkStore>();
  }

  buffered_chunk_store->SetCacheCapacity(64 << 20);

  std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority(
      new chunk_actions::ChunkActionAuthority(buffered_chunk_store));
  std::shared_ptr<LocalChunkManager> local_chunk_manager(
      new LocalChunkManager(buffered_chunk_store,
                            local_chunk_manager_path,
                            chunk_lock_path,
                            delay));

  return std::shared_ptr<RemoteChunkStore>(
      new RemoteChunkStore(buffered_chunk_store,
                           local_chunk_manager,
                           chunk_action_authority));
}

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
