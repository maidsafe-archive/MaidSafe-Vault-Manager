/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  remote_chunk_store.cc
 * @brief Class implementing %ChunkStore wrapper for %ChunkManager.
 * @date  2011-05-18
 */

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

// #include "boost/archive/text_oarchive.hpp"
// #include "boost/archive/text_iarchive.hpp"
// #include "boost/serialization/set.hpp"
// #include "boost/serialization/list.hpp"
// #include "boost/serialization/utility.hpp"
// #include "boost/asio/deadline_timer.hpp"

#include "maidsafe/common/utils.h"

#include "maidsafe/private/log.h"
#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_store/local_chunk_manager.h"

namespace args = std::placeholders;

namespace maidsafe {

namespace priv {

namespace chunk_store {

enum RcsReturnCode {
  kWaitSuccess = 0,
  kWaitCancelled = -1,
  kWaitTimeout = -2
};

/// Default maximum number of operations to be processed in parallel.
const int kMaxActiveOps(4);
/// Time to wait in WaitForCompletion before failing.
const boost::posix_time::time_duration kCompletionWaitTimeout(
    boost::posix_time::seconds(90));
/// Time to wait in WaitForConflictingOps before failing.
const boost::posix_time::time_duration kOperationWaitTimeout(
    boost::posix_time::seconds(60));

const std::string RemoteChunkStore::kOpName[] = { "get",
                                                  "store",
                                                  "modify",
                                                  "delete" };

RemoteChunkStore::RemoteChunkStore(
    std::shared_ptr<BufferedChunkStore> chunk_store,
    std::shared_ptr<ChunkManager> chunk_manager,
    std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority)
    : chunk_store_(chunk_store),
      chunk_manager_(chunk_manager),
      chunk_action_authority_(chunk_action_authority),
      cm_get_conn_(),
      cm_store_conn_(),
      cm_modify_conn_(),
      cm_delete_conn_(),
      mutex_(),
      cond_var_(),
      max_active_ops_(kMaxActiveOps),
      active_ops_count_(0),
      completion_wait_timeout_(kCompletionWaitTimeout),
      operation_wait_timeout_(kOperationWaitTimeout),
      pending_ops_(),
      failed_ops_(),
      op_count_(),
      op_success_count_(),
      op_skip_count_(),
      op_size_() {
  cm_get_conn_ = chunk_manager_->sig_chunk_got()->connect(std::bind(
      &RemoteChunkStore::OnOpResult, this, kOpGet, args::_1, args::_2));
  cm_store_conn_ = chunk_manager_->sig_chunk_stored()->connect(std::bind(
      &RemoteChunkStore::OnOpResult, this, kOpStore, args::_1, args::_2));
  cm_modify_conn_ = chunk_manager_->sig_chunk_modified()->connect(std::bind(
      &RemoteChunkStore::OnOpResult, this, kOpModify, args::_1, args::_2));
  cm_delete_conn_ = chunk_manager_->sig_chunk_deleted()->connect(std::bind(
      &RemoteChunkStore::OnOpResult, this, kOpDelete, args::_1, args::_2));
}

RemoteChunkStore::~RemoteChunkStore() {
  cm_get_conn_.disconnect();
  cm_store_conn_.disconnect();
  cm_modify_conn_.disconnect();
  cm_delete_conn_.disconnect();

  boost::mutex::scoped_lock lock(mutex_);
  for (int op = kOpGet; op <= kOpDelete; ++op)
    DLOG(INFO) << "~RemoteChunkStore() - Could " << kOpName[op] << " "
               << op_success_count_[op] << " and skip " << op_skip_count_[op]
               << " of " << op_count_[op] << " chunks ("
               << BytesToBinarySiUnits(op_size_[op]) << ").";

  std::string output;
  for (auto it = pending_ops_.begin(); it != pending_ops_.end(); ++it)
    output += "\n\t" + HexSubstr(it->left) + " (" + kOpName[it->info.op_type]
            + (it->info.active ? ", active" : "") + ")";
  if (!output.empty())
    DLOG(WARNING) << "~RemoteChunkStore() - " << pending_ops_.size()
                  << " pending operations, " << active_ops_count_ << " active :"
                  << output;

  output.clear();
  for (auto it = failed_ops_.begin(); it != failed_ops_.end(); ++it)
    output += "\n\t" + HexSubstr(it->first) + " (" + kOpName[it->second] + ")";
  if (!output.empty())
    DLOG(WARNING) << "~RemoteChunkStore() - " << failed_ops_.size()
                  << " failed operations:" << output;

  active_ops_count_ = 0;
  pending_ops_.clear();
  failed_ops_.clear();
}

std::string RemoteChunkStore::Get(const std::string &name,
                                  const ValidationData &validation_data) {
  DLOG(INFO) << "Get - " << HexSubstr(name);

  boost::mutex::scoped_lock lock(mutex_);

  if (chunk_action_authority_->Cacheable(name) &&
      pending_ops_.left.count(name) == 0) {
    std::string content(chunk_store_->Get(name));
    if (!content.empty())
      return content;
  }

  uint32_t id(EnqueueOp(name, OperationData(kOpGet, nullptr, validation_data),
                        &lock));
  ProcessPendingOps(&lock);
  if (!WaitForGetOps(name, id, &lock)) {
    DLOG(ERROR) << "Get - Timed out for " << HexSubstr(name);
    return "";
  }

  std::string content(chunk_store_->Get(name));
  if (content.empty()) {
    DLOG(ERROR) << "Get - Failed retrieving " << HexSubstr(name);
    return "";
  }

  // check if there is a get op for this chunk following
  auto it = pending_ops_.left.begin();
  if (it != pending_ops_.left.end() && it->info.op_type == kOpGet) {
    pending_ops_.left.erase(it);  // trigger next one
  } else {
    DLOG(INFO) << "Get - Done, deleting " << HexSubstr(name);
    if (chunk_action_authority_->Cacheable(name))
      chunk_store_->MarkForDeletion(name);
    else
      chunk_store_->Delete(name);
  }

  return content;
}

bool RemoteChunkStore::Store(const std::string &name,
                             const std::string &content,
                             const OpFunctor &callback,
                             const ValidationData &validation_data) {
  DLOG(INFO) << "Store - " << HexSubstr(name);

  boost::mutex::scoped_lock lock(mutex_);
  uint32_t id(EnqueueOp(name, OperationData(kOpStore, callback,
                                            validation_data), &lock));
  int result(WaitForConflictingOps(name, kOpStore, id, &lock));
  if (result != kWaitSuccess) {
    DLOG(WARNING) << "Store - Terminated early for " << HexSubstr(name);
    return result == kWaitCancelled;
  }

  if (!chunk_action_authority_->Store(name,
                                      content,
                                      validation_data.key_pair.public_key)) {
    DLOG(ERROR) << "Store - Could not store " << HexSubstr(name) << " locally.";
    pending_ops_.right.erase(id);
    cond_var_.notify_all();
    return false;
  }

  ProcessPendingOps(&lock);
  return true;
}

bool RemoteChunkStore::Delete(const std::string &name,
                              const OpFunctor &callback,
                              const ValidationData &validation_data) {
  DLOG(INFO) << "Delete - " << HexSubstr(name);

  boost::mutex::scoped_lock lock(mutex_);
  uint32_t id(EnqueueOp(name, OperationData(kOpDelete, callback,
                                            validation_data), &lock));
  int result(WaitForConflictingOps(name, kOpDelete, id, &lock));
  if (result != kWaitSuccess) {
    DLOG(WARNING) << "Delete - Terminated early for " << HexSubstr(name);
    return result == kWaitCancelled;
  }

  if (!chunk_action_authority_->Delete(name,
                                       chunk_action_authority_->Version(name),
                                       validation_data.ownership_proof,
                                       validation_data.key_pair.public_key)) {
    DLOG(ERROR) << "Delete - Could not delete " << HexSubstr(name)
                << " locally.";
    pending_ops_.right.erase(id);
    cond_var_.notify_all();
    return false;
  }

  ProcessPendingOps(&lock);
  return true;
}

bool RemoteChunkStore::Modify(const std::string &name,
                              const std::string &content,
                              const OpFunctor &callback,
                              const ValidationData &validation_data) {
  DLOG(INFO) << "Modify - " << HexSubstr(name);

  if (!chunk_action_authority_->Modifiable(name)) {
    DLOG(ERROR) << "Modify - Type of chunk " << HexSubstr(name)
                << " not supported.";
    return false;
  }

  boost::mutex::scoped_lock lock(mutex_);
  OperationData op_data(kOpModify, callback, validation_data);
  op_data.content = content;
  EnqueueOp(name, op_data, &lock);
//   uint32_t id(EnqueueOp(name, op_data, &lock));
//   int result(WaitForConflictingOps(name, kOpModify, id, &lock));
//   if (result != kWaitSuccess) {
//     DLOG(WARNING) << "Modify - Terminated early for " << HexSubstr(name);
//     return result == kWaitCancelled;
//   }

  ProcessPendingOps(&lock);
  return true;
}

bool RemoteChunkStore::WaitForCompletion() {
  boost::mutex::scoped_lock lock(mutex_);
  while (!pending_ops_.empty()) {
    DLOG(INFO) << "WaitForCompletion - " << pending_ops_.size()
               << " pending operations, " << active_ops_count_
               << " of them active...";
    if (!cond_var_.timed_wait(lock, completion_wait_timeout_)) {
      DLOG(ERROR) << "WaitForCompletion - Timed out with "
                  << pending_ops_.size() << " pending operations, "
                  << active_ops_count_ << " of them active.";
      return false;
    }
  }
  DLOG(INFO) << "WaitForCompletion - Done.";
  return true;
}

void RemoteChunkStore::OnOpResult(const OperationType &op_type,
                                  const std::string &name,
                                  const int &result) {
  boost::mutex::scoped_lock lock(mutex_);

  // find first matching and active op
  auto it = pending_ops_.left.find(name);
  if (it == pending_ops_.left.end() || it->info.op_type != op_type ||
      !it->info.active) {
    DLOG(WARNING) << "OnOpResult - Unrecognised result for op '"
                  << kOpName[op_type] << "' and chunk " << HexSubstr(name)
                  << " received. (" << result << ")";
    return;
  }

  // statistics
  if (result == kSuccess) {
    ++op_success_count_[op_type];
    switch (op_type) {
      case kOpGet:
      case kOpStore:
        op_size_[op_type] += chunk_store_->Size(name);
        break;
      case kOpModify:
        op_size_[op_type] += it->info.content.size();
        break;
      default:
        break;
    }
  } else {
    DLOG(ERROR) << "OnOpResult - Failed to " << kOpName[op_type] << " "
                << HexSubstr(name) << " (" << result << ")";
    failed_ops_.insert(std::make_pair(name, op_type));
  }

  if (op_type == kOpStore) {
    // don't keep non-cacheable chunks locally
    DLOG(INFO) << "OnOpResult - Store done, deleting " << HexSubstr(name);
    if (chunk_action_authority_->Cacheable(name))
      chunk_store_->MarkForDeletion(name);
    else
      chunk_store_->Delete(name);
    // NOTE cacheable chunks that failed to store will remain locally
  }

  OpFunctor callback(it->info.callback);
  --active_ops_count_;
  pending_ops_.left.erase(it);
  cond_var_.notify_all();

  if (callback) {
    lock.unlock();
    callback(result == kSuccess);
    lock.lock();
  }

  ProcessPendingOps(&lock);
}

int RemoteChunkStore::WaitForConflictingOps(const std::string &name,
                                            const OperationType &op_type,
                                            const uint32_t &transaction_id,
                                            boost::mutex::scoped_lock *lock) {
  if (transaction_id == 0)  // our op is redundant
    return kWaitCancelled;

  while (pending_ops_.left.count(name) > 1) {
    if (!cond_var_.timed_wait(*lock, operation_wait_timeout_)) {
      DLOG(ERROR) << "WaitForConflictingOps - Timed out trying to "
                  << kOpName[op_type] << " " << HexSubstr(name) << " with "
                  << pending_ops_.left.count(name) << " pending operations.";
      pending_ops_.right.erase(transaction_id);
      failed_ops_.insert(std::make_pair(name, op_type));
      return kWaitTimeout;
    }
    if (pending_ops_.right.count(transaction_id) == 0) {
      DLOG(WARNING) << "WaitForConflictingOps - Operation to "
                    << kOpName[op_type] << " " << HexSubstr(name)
                    << " with transaction ID " << transaction_id
                    << " was cancelled.";
      return kWaitCancelled;
    }
  }
  return kWaitSuccess;
}

bool RemoteChunkStore::WaitForGetOps(const std::string &name,
                                     const uint32_t &transaction_id,
                                     boost::mutex::scoped_lock *lock) {
  while (pending_ops_.right.count(transaction_id) > 0) {
    if (!cond_var_.timed_wait(*lock, kOperationWaitTimeout)) {
      DLOG(ERROR) << "WaitForGetOps - Timed out for " << HexSubstr(name)
                  << " with " << pending_ops_.left.count(name)
                  << " pending operations.";
      pending_ops_.right.erase(transaction_id);
      failed_ops_.insert(std::make_pair(name, kOpGet));
      return false;
    }
  }
  return true;
}

uint32_t RemoteChunkStore::EnqueueOp(const std::string &name,
                                     const OperationData &op_data,
                                     boost::mutex::scoped_lock *lock) {
  ++op_count_[op_data.op_type];

  // Are we able to cancel a previous op for this chunk?
  auto it = pending_ops_.left.upper_bound(name);
  if (pending_ops_.left.lower_bound(name) != it) {
    --it;
//     DLOG(INFO) << "EnqueueOp - Op '" << kOpName[op_data.op_type]
//                << "', found prev '" << kOpName[it->info.op_type]
//                << "', chunk " << HexSubstr(name) << ", "
//                << (it->info.active ? "active" : "inactive");
    if (!it->info.active) {
      bool cancel_prev(false), cancel_curr(false);
      if (op_data.op_type == kOpModify &&
          it->info.op_type == kOpModify &&
          chunk_action_authority_->ModifyReplaces(name)) {
        cancel_prev = true;
      } else if (op_data.op_type == kOpDelete &&
                 (it->info.op_type == kOpModify ||
                  it->info.op_type == kOpStore)) {
        // NOTE has potential side effects (multiple stores, unauth. delete)
        cancel_prev = true;
        cancel_curr= true;
      }

      if (cancel_prev) {
        DLOG(INFO) << "EnqueueOp - Cancel previous '"
                   << kOpName[it->info.op_type] << "' due to '"
                   << kOpName[op_data.op_type] << "' for "
                   << HexSubstr(name);
        OpFunctor callback(it->info.callback);
        ++op_skip_count_[it->info.op_type];
        pending_ops_.left.erase(it);
        cond_var_.notify_all();
        if (it->info.op_type == kOpModify && callback) {
          // run callback, because Modify doesn't block
          lock->unlock();
          callback(true);
          lock->lock();
        }
      }
      if (cancel_curr) {
        ++op_skip_count_[op_data.op_type];
        return 0;
      }
    }
  }

  uint32_t id;
  do {
    id = RandomUint32();
  } while (id == 0 || pending_ops_.right.count(id) > 0);
  pending_ops_.push_back(OperationBimap::value_type(name, id, op_data));
  return id;
}

void RemoteChunkStore::ProcessPendingOps(boost::mutex::scoped_lock *lock) {
//   DLOG(INFO) << "ProcessPendingOps - " << active_ops_count_ << " of max "
//              << max_active_ops_ << " ops active.";
  while (active_ops_count_ < max_active_ops_) {
    std::string name;
    OperationData op_data;
    {
      std::set<std::string> active_ops_;
      auto it = pending_ops_.begin();  // always (re-)start from beginning!
      while (it != pending_ops_.end()) {
        if (it->info.active)
          active_ops_.insert(it->left);
        else if (active_ops_.count(it->left) == 0)
          break;
        ++it;
      }
      if (it == pending_ops_.end()) {
//         if (!pending_ops_.empty())
//           DLOG(INFO) << "ProcessPendingOps - " << pending_ops_.size()
//                     << " ops active or waiting for dependencies...";
        return;  // no op found that an currently be processed
      }

      DLOG(INFO) << "ProcessPendingOps - About to " << kOpName[it->info.op_type]
                << " chunk " << HexSubstr(it->left);

      it->info.active = true;
      name = it->left;
      op_data = it->info;
    }

    ++active_ops_count_;
    lock->unlock();
    switch (op_data.op_type) {
      case kOpGet:
        chunk_manager_->GetChunk(name,
                                 op_data.owner_key_id,
                                 op_data.owner_public_key,
                                 op_data.ownership_proof);
        break;
      case kOpStore:
        chunk_manager_->StoreChunk(name,
                                   op_data.owner_key_id,
                                   op_data.owner_public_key);
        break;
      case kOpModify:
        chunk_manager_->ModifyChunk(name,
                                    op_data.content,
                                    op_data.owner_key_id,
                                    op_data.owner_public_key);
        break;
      case kOpDelete:
        chunk_manager_->DeleteChunk(name,
                                    op_data.owner_key_id,
                                    op_data.owner_public_key,
                                    op_data.ownership_proof);
        break;
    }
    lock->lock();
  }
}

/*

void RemoteChunkStore::StoreOpBackups(
    std::shared_ptr<boost::asio::deadline_timer> timer,
    const std::string &pmid) {
  timer->expires_from_now(boost::posix_time::seconds(10));
  timer->async_wait(std::bind(
      &RemoteChunkStore::DoOpBackups, this, arg::_1, pmid, timer));
}

void RemoteChunkStore::DoOpBackups(
    boost::system::error_code error,
    const std::string &pmid,
    std::shared_ptr<boost::asio::deadline_timer> timer) {
  if (error)
    DLOG(ERROR) << "Error " << error << " occurred.";
  std::stringstream op_stream(std::stringstream::in |
                              std::stringstream::out);
  int result = op_archiving::Serialize(*this, &op_stream);
  if (result != kSuccess)
    DLOG(ERROR) << "Failed to serialize ops.";
  if (!chunk_store_->Delete("RemoteChunkStore" + pmid))
      DLOG(ERROR) << "Failed to delete old ops.";
  if (!chunk_store_->Store("RemoteChunkStore" + pmid, op_stream.str()))
    DLOG(ERROR) << "Failed to store ops.";
  // timer.reset();
  StoreOpBackups(timer, pmid);
}

template<class Archive>
void RemoteChunkStore::serialize(Archive &archive, const unsigned int) {  // NOLINT
  boost::mutex::scoped_lock lock(mutex_);
  archive & active_mod_ops_;
  archive & pending_mod_ops_;
  archive & failed_hashable_ops_;
  archive & failed_non_hashable_store_ops_;
  std::list<std::string> removable_chunks(chunk_store_->GetRemovableChunks());
  archive & removable_chunks;
}

namespace op_archiving {

  int Serialize(const maidsafe::pd::RemoteChunkStore &remote_chunk_store,
                std::stringstream *output_stream) {
  if (!output_stream) {
    return -1;
  }
  try {
    boost::archive::text_oarchive oa(*output_stream);
    oa << remote_chunk_store;
  } catch(const std::exception &e) {
    DLOG(ERROR) << e.what();
    return -1;
  }
  return kSuccess;
}

int Deserialize(std::stringstream *input_stream,
                maidsafe::pd::RemoteChunkStore &remote_chunk_store) {
  if (!input_stream)
    return -1;
  try {
    boost::archive::text_iarchive ia(*input_stream);
    ia >> remote_chunk_store;
  } catch(const std::exception &e) {
    DLOG(ERROR) << e.what();
    return -1;
  }
  return kSuccess;
}

}  // namespace op_archiving

*/

std::shared_ptr<RemoteChunkStore> CreateLocalChunkStore(
    const fs::path &base_dir,
    boost::asio::io_service &asio_service,  // NOLINT (Dan)
    const boost::posix_time::time_duration &millisecs) {
  std::shared_ptr<BufferedChunkStore> buffered_chunk_store(
      new BufferedChunkStore(asio_service));
  std::string buffered_chunk_store_dir("buffered_chunk_store" +
                                       RandomAlphaNumericString(8));
  buffered_chunk_store->Init(base_dir / buffered_chunk_store_dir);
  std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority(
      new chunk_actions::ChunkActionAuthority(buffered_chunk_store));
  std::shared_ptr<LocalChunkManager> local_chunk_manager(
      new LocalChunkManager(buffered_chunk_store,
                            base_dir / "local_chunk_manager",
                            millisecs));

  return std::make_shared<RemoteChunkStore>(buffered_chunk_store,
                                            local_chunk_manager,
                                            chunk_action_authority);
}

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
