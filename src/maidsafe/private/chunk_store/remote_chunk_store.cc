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

enum RcsReturnCode {
  kWaitSuccess = 0,
  kWaitCancelled = -1,
  kWaitTimeout = -2
};

/// Default maximum number of operations to be processed in parallel.
const int kMaxActiveOps(4);
/// Time to wait in WaitForCompletion before failing.
const bptime::time_duration KCompletionWaitTimeout(bptime::minutes(3));

const std::string RemoteChunkStore::kOpName[] = { "get",
                                                  "store",
                                                  "modify",
                                                  "delete" };

RemoteChunkStore::RemoteChunkStore(
    std::shared_ptr<BufferedChunkStore> chunk_store,
    std::shared_ptr<ChunkManager> chunk_manager,
    std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority)
    : sig_chunk_stored_(new ChunkManager::ChunkStoredSig),
      sig_chunk_modified_(new ChunkManager::ChunkModifiedSig),
      sig_chunk_deleted_(new ChunkManager::ChunkDeletedSig),
      chunk_store_(chunk_store),
      chunk_manager_(chunk_manager),
      chunk_action_authority_(chunk_action_authority),
      cm_get_conn_(),
      cm_store_conn_(),
      cm_modify_conn_(),
      cm_delete_conn_(),
      mutex_(),
      cond_var_(),
      max_active_ops_(kMaxActiveOps),
      active_ops_(),
      pending_ops_(),
      failed_ops_() /*,
      op_count_({0, 0, 0, 0}),
      op_success_count_({0, 0, 0, 0}),
      op_size_({0, 0, 0, 0})*/ {
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
/*
  DLOG(INFO) << "~RemoteChunkStore() - Retrieved " << get_success_count_
             << " of " << get_op_count_ << " chunks ("
             << BytesToBinarySiUnits(get_total_size_) << ").";
  DLOG(INFO) << "~RemoteChunkStore() - Stored " << store_success_count_
             << " of " << store_op_count_ << " chunks ("
             << BytesToBinarySiUnits(store_total_size_) << ").";
  DLOG(INFO) << "~RemoteChunkStore() - Modified " << modify_success_count_
             << " of " << modify_op_count_ << " chunks ("
             << BytesToBinarySiUnits(modify_total_size_) << ").";
  DLOG(INFO) << "~RemoteChunkStore() - Deleted " << delete_success_count_
             << " of " << delete_op_count_ << " chunks.";

  std::string output;
  for (auto it = failed_hashable_ops_.begin(); it != failed_hashable_ops_.end();
       ++it)
    output += "\n\t" + HexSubstr(it->first) + " (" + kOpName[it->second.op_type]
            + ")";
  if (!output.empty())
    DLOG(WARNING) << "~RemoteChunkStore() - " << failed_hashable_ops_.size()
                  << " failed hashable operations:" << output;

  output.clear();
  for (auto it = failed_non_hashable_store_ops_.begin();
       it != failed_non_hashable_store_ops_.end(); ++it)
    output += "\n\t" + HexSubstr(*it);
  if (!output.empty())
    DLOG(WARNING) << "~RemoteChunkStore() - "
                  << failed_non_hashable_store_ops_.size()
                  << " critically failed non-hashable store operations:"
                  << output;

  output.clear();
  for (auto it = pending_mod_ops_.begin(); it != pending_mod_ops_.end(); ++it)
    output += "\n\t" + HexSubstr(it->first) + " (" + kOpName[it->second.op_type]
            + ")";
  if (!output.empty())
    DLOG(WARNING) << "~RemoteChunkStore() - " << pending_mod_ops_.size()
                  << " pending operations:" << output;

  output.clear();
  for (auto it = active_mod_ops_.begin(); it != active_mod_ops_.end(); ++it)
    output += "\n\t" + HexSubstr(*it) + " (store, modify or delete)";
  for (auto it = active_get_ops_.begin(); it != active_get_ops_.end(); ++it)
    output += "\n\t" + HexSubstr(*it) + " (get)";
  if (!output.empty())
    DLOG(WARNING) << "~RemoteChunkStore() - " << active_ops_count_
                  << " active operations:" << output;
*/
  active_ops_.clear();
  pending_ops_.clear();
  failed_ops_.clear();
}


std::string RemoteChunkStore::Get(
    const std::string &name,
    const ValidationData &validation_data) const {
  DLOG(INFO) << "Get - " << HexSubstr(name);
  std::string result(DoGet(name, validation_data));
  if (result.empty())
    DLOG(ERROR) << "Get - Could not retrieve " << HexSubstr(name);
  return result;
}

bool RemoteChunkStore::Get(const std::string &name,
                           const fs::path &sink_file_name,
                           const ValidationData &validation_data) const {
  DLOG(INFO) << "Get - " << HexSubstr(name);
  std::string result(DoGet(name, validation_data));
  if (result.empty()) {
    DLOG(ERROR) << "Get - Could not retrieve " << HexSubstr(name);
    return false;
  }
  return WriteFile(sink_file_name, result);
}

void RemoteChunkStore::Get(const std::string &name,
                           const ValidationData &validation_data,
                           GetFunctor callback) {
  // TODO(Steve) ..........
}

bool RemoteChunkStore::Store(const std::string &name,
                             const std::string &content,
                             const ValidationData &validation_data) {
  DLOG(INFO) << "Store - " << HexSubstr(name);

  boost::mutex::scoped_lock lock(mutex_);
  uint32_t id(EnqueueOp(name, OperationData(kOpStore, validation_data)));
  int result(WaitForConflictingOps(name, kOpStore, id, &lock));
  if (result != kWaitSuccess) {
    DLOG(WARNING) << "Store - Terminated early for " << HexSubstr(name);
    // TODO(Steve) remove pending entry !!!
    return result == kWaitCancelled;
  }

  if (!chunk_action_authority_->Store(name,
                                      content,
                                      validation_data.key_pair.public_key)) {
    DLOG(ERROR) << "Store - Could not store " << HexSubstr(name) << " locally.";
    return false;
  }

  ProcessPendingOps(&lock);
  return true;
}

bool RemoteChunkStore::Store(const std::string &name,
                             const fs::path &source_file_name,
                             bool delete_source_file,
                             const ValidationData &validation_data) {
  DLOG(INFO) << "Store - " << HexSubstr(name);

  boost::mutex::scoped_lock lock(mutex_);
  uint32_t id(EnqueueOp(name, OperationData(kOpStore, validation_data)));
  int result(WaitForConflictingOps(name, kOpStore, id, &lock));
  if (result != kWaitSuccess) {
    DLOG(WARNING) << "Store - Terminated early for " << HexSubstr(name);
    return result == kWaitCancelled;
  }

  if (!chunk_action_authority_->Store(name,
                                      source_file_name,
                                      delete_source_file,
                                      validation_data.key_pair.public_key)) {
    DLOG(ERROR) << "Store - Could not store " << HexSubstr(name) << " locally.";
    return false;
  }

  ProcessPendingOps(&lock);
  return true;
}

bool RemoteChunkStore::Delete(const std::string &name,
                              const ValidationData &validation_data) {
  DLOG(INFO) << "Delete - " << HexSubstr(name);

  boost::mutex::scoped_lock lock(mutex_);
  uint32_t id(EnqueueOp(name, OperationData(kOpDelete, validation_data)));
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
    return false;
  }

  ProcessPendingOps(lock);
  return true;
}

bool RemoteChunkStore::Modify(const std::string &name,
                              const std::string &content,
                              const ValidationData &validation_data) {
  DLOG(INFO) << "Modify - " << HexSubstr(name);

  if (!chunk_action_authority_->Modifiable(name)) {
    DLOG(ERROR) << "Store - Type of chunk " << HexSubstr(name)
                << " not supported.";
    return false;
  }

  boost::mutex::scoped_lock lock(mutex_);
  OperationData op_data(kOpModify, validation_data);
  op_data.content = content;
  uint32_t id(EnqueueOp(name, op_data));
  int result(WaitForConflictingOps(name, kOpModify, id, &lock));
  if (result != kWaitSuccess) {
    DLOG(WARNING) << "Modify - Terminated early for " << HexSubstr(name);
    return result == kWaitCancelled;
  }

  ProcessPendingOps(&lock);
  return true;
}

bool RemoteChunkStore::Modify(const std::string &name,
                              const fs::path &source_file_name,
                              bool delete_source_file,
                              const ValidationData &validation_data) {
  DLOG(INFO) << "Modify - " << HexSubstr(name);
  std::string content;
  if (!ReadFile(source_file_name, &content)) {
    DLOG(ERROR) << "Modify - Failed to read file for chunk " << HexSubstr(name);
    return false;
  }
  if (!Modify(name, content, validation_data)) {
    DLOG(ERROR) << "Modify - Failed to modify chunk " << HexSubstr(name);
    return false;
  }
  boost::system::error_code ec;
  if (delete_source_file)
    fs::remove(source_file_name, ec);
  return true;
}

bool RemoteChunkStore::WaitForCompletion() {
  boost::mutex::scoped_lock lock(mutex_);
  while (!pending_ops_.empty() && !active_ops_.empty()) {
    DLOG(INFO) << "WaitForCompletion - " << pending_ops_.size()
               << " pending and " << active_ops_.size()
               << " active operations...";
    if (!cond_var_.timed_wait(lock, KCompletionWaitTimeout)) {
      DLOG(ERROR) << "WaitForCompletion - Timed out with "
                  << pending_ops_.size() << " pending and "
                  << active_ops_.size() << " active operations.";
      return false;
    }
  }
  DLOG(INFO) << "WaitForCompletion - Done.";
  return true;
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

*/

void RemoteChunkStore::OnOpResult(const OperationType &op_type,
                                  const std::string &name,
                                  const int &result) {
  {
    boost::mutex::scoped_lock lock(mutex_);
    --active_ops_count_;

    // statistics
    if (result == kSuccess) {
      if ((op_type == kOpStore || op_type == kOpDelete) &&
          !chunk_action_authority_->Cacheable(name))
        failed_non_hashable_store_ops_.erase(name);
    } else {
      if (chunk_action_authority_->Cacheable(name))
        failed_hashable_ops_.push_back(std::make_pair(name,
                                                      OperationData(op_type)));
      else if (op_type == kOpStore)
        failed_non_hashable_store_ops_.insert(name);
      DLOG(ERROR) << "OnOpResult - Op '" << kOpName[op_type] << "' for "
                  << HexSubstr(name) << " failed. (" << result << ")";
      // TODO(Steve) re-enqueue op for retry, but needs counter
    }

    switch (op_type) {
      case kOpGet:
        active_get_ops_.erase(name);
        if (result == kSuccess) {
          ++get_success_count_;
          get_total_size_ += chunk_store_->Size(name);
        }
        break;
      case kOpStore:
        active_mod_ops_.erase(name);
        if (result == kSuccess) {
          ++store_success_count_;
          store_total_size_ += chunk_store_->Size(name);
        }
        // don't keep non-cacheable chunks locally
        DLOG(INFO) << "OnOpResult - Store done, deleting " << HexSubstr(name);
        if (chunk_action_authority_->Cacheable(name))
          chunk_store_->MarkForDeletion(name);
        else
          chunk_store_->Delete(name);
        // NOTE cacheable chunks that failed to store will remain locally
        break;
      case kOpModify:
        active_mod_ops_.erase(name);
        if (result == kSuccess) {
          ++modify_success_count_;
          // modify_total_size_ += ...content.size(); // TODO(Steve) mod size
        }
        break;
      case kOpDelete:
        active_mod_ops_.erase(name);
        if (result == kSuccess)
          ++delete_success_count_;
        break;
    }

    cond_var_.notify_all();
  }

  // pass signal on
  switch (op_type) {
    case kOpStore:
      (*sig_chunk_stored_)(name, result);
      break;
    case kOpModify:
      (*sig_chunk_modified_)(name, result);
      break;
    case kOpDelete:
      (*sig_chunk_deleted_)(name, result);
      break;
    default:
      break;
  }

  boost::mutex::scoped_lock lock(mutex_);
  ProcessPendingOps(&lock);
}

std::string RemoteChunkStore::DoGet(
    const std::string &name,
    const ValidationData &validation_data) const {
  ScopedLockPtr lock(new boost::mutex::scoped_lock(mutex_));
  if (!WaitForConflictingOp(name, kOpGet, lock))
    return "";

  // TODO(Steve) ...... callbacks

  if (chunk_action_authority_->Cacheable(name)) {
    std::string content(chunk_store_->Get(name));
    if (!content.empty())
      return content;
  }

  waiting_getters_.insert(name);

  if (active_get_ops_.count(name) == 0) {
    // new Get op required
    active_get_ops_.insert(name);
    ++get_op_count_;

    while (active_ops_count_ >= max_active_ops_)
      cond_var_.wait(lock);

    ++active_ops_count_;
    lock.unlock();
    chunk_manager_->GetChunk(name,
                             validation_data.key_pair.identity,
                             validation_data.key_pair.public_key,
                             validation_data.ownership_proof);
    lock.lock();
  }

  // wait for retrieval
  while (active_get_ops_.count(name) > 0)
    cond_var_.wait(lock);

  waiting_getters_.erase(name);

  std::string content(chunk_store_->Get(name));
  if (waiting_getters_.find(name) == waiting_getters_.end()) {
    DLOG(INFO) << "DoGet - Get done, deleting " << HexSubstr(name);
    if (chunk_action_authority_->Cacheable(name))
      chunk_store_->MarkForDeletion(name);
    else
      chunk_store_->Delete(name);
  }
  return content;
}

int RemoteChunkStore::WaitForConflictingOps(const std::string &name,
                                            const OperationType &op_type,
                                            const uint32_t &transaction_id,
                                            boost::mutex::scoped_lock *lock) {
  while (active_ops_.count(name) > 0 && pending_ops_.left.count(name) > 1) {
    if (!cond_var_.timed_wait(*lock, KCompletionWaitTimeout)) {
      DLOG(ERROR) << "WaitForConflictingOp - Timed out trying to "
                  << kOpName[op_type] << " " << HexSubstr(name) << " with "
                  << pending_ops_.left.count(name) << " pending and "
                  << active_ops_.count(name) << " active operations.";
      return kWaitTimeout;
    }
    if (pending_ops_.right.count(transaction_id) == 0) {
      DLOG(WARNING) << "WaitForConflictingOp - Operation to "
                    << kOpName[op_type] << " " << HexSubstr(name)
                    << " with transaction ID " << transaction_id
                    << " was cancelled.";
      return kWaitCancelled;
    }
  }
  return kWaitSuccess;
}

uint32_t RemoteChunkStore::EnqueueOp(const std::string &name,
                                     const OperationData &op_data) {
  ++op_count_[op_data.op_type];

  // TODO(Steve) cancel redundant pending ops, trigger cond var

//       // delete cancels out previous store for this chunk
//       for (auto rit = pending_mod_ops_.rbegin();
//             rit != pending_mod_ops_.rend(); ++rit) {
//         if (rit->first == name && rit->second.op_type == kOpStore) {
//           pending_mod_ops_.erase(--rit.base());
//           --store_op_count_;
//           DLOG(INFO) << "EnqueueModOp - Ignored delete and removed pending "
//                       << "store for " << HexSubstr(name);
//           return;
//         }
//       }

  uint32_t id;
  do {
    id = RandomUint32();
  } while (pending_ops_.right.count(id) > 0);
  pending_ops_.push_back(OperationBimap::value_type(name, id, op_data));
  return id;
}

void RemoteChunkStore::ProcessPendingOps(boost::mutex::scoped_lock *lock) {
  while (active_ops_count_ < max_active_ops_) {
    auto it = pending_mod_ops_.begin();  // always (re-)start from beginning!
    while (it != pending_mod_ops_.end() &&
           active_mod_ops_.count(it->first) > 0)
      ++it;
    if (it == pending_mod_ops_.end())
      return;  // no op found that can currently be processed

    std::string name(it->first);
    OperationData data(it->second);
    it = pending_mod_ops_.erase(it);
    ++active_ops_count_;
    active_mod_ops_.insert(name);

    lock->unlock();
    switch (data.op_type) {
      case kOpStore:
        chunk_manager_->StoreChunk(name,
                                   data.owner_key_id,
                                   data.owner_public_key);
        break;
      case kOpModify:
        chunk_manager_->ModifyChunk(name,
                                    data.content,
                                    data.owner_key_id,
                                    data.owner_public_key);
        break;
      case kOpDelete:
        chunk_manager_->DeleteChunk(name,
                                    data.owner_key_id,
                                    data.owner_public_key,
                                    data.ownership_proof);
        break;
      default:
        // Get is handled separately
        break;
    }
    lock->lock();
  }
}

/*

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
    boost::asio::io_service &asio_service) {  // NOLINT (Dan)
  std::shared_ptr<BufferedChunkStore> buffered_chunk_store(
      new BufferedChunkStore(asio_service));
  std::string buffered_chunk_store_dir("buffered_chunk_store" +
                                       RandomAlphaNumericString(8));
  buffered_chunk_store->Init(base_dir / buffered_chunk_store_dir);
  std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority(
      new chunk_actions::ChunkActionAuthority(buffered_chunk_store));
  std::shared_ptr<LocalChunkManager> local_chunk_manager(
      new LocalChunkManager(buffered_chunk_store,
                            base_dir / "local_chunk_manager"));

  return std::make_shared<RemoteChunkStore>(buffered_chunk_store,
                                            local_chunk_manager,
                                            chunk_action_authority);
}

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
