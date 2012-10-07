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

#include "maidsafe/private/chunk_store/local_chunk_manager.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_type.h"
#include "maidsafe/private/chunk_store/file_chunk_store.h"
#include "maidsafe/private/chunk_store/threadsafe_chunk_store.h"


namespace maidsafe {

namespace priv {

namespace chunk_store {

LocalChunkManager::LocalChunkManager(std::shared_ptr<ChunkStore> normal_local_chunk_store,
                                     const fs::path& simulation_directory,
                                     const fs::path& lock_directory,
                                     const boost::posix_time::time_duration& millisecs)
    : ChunkManager(normal_local_chunk_store),
      simulation_chunk_store_(),
      simulation_chunk_action_authority_(),
      get_wait_(millisecs),
      action_wait_(millisecs * 3),
      lock_directory_(),
      current_transactions_() {
  std::shared_ptr<FileChunkStore> file_chunk_store(new FileChunkStore);
  fs::path local_version_directory;
  if (simulation_directory.empty()) {
    boost::system::error_code error_code;
    local_version_directory = fs::temp_directory_path(error_code);
    if (error_code) {
      LOG(kError) << "Failed to get temp directory: " << error_code.message();
      return;
    }
    local_version_directory /= "LocalUserCredentials";
  } else {
    local_version_directory = simulation_directory;
  }
  lock_directory_ =  lock_directory;
  boost::system::error_code error_code;
  if (!fs::exists(lock_directory_, error_code))
    fs::create_directory(lock_directory_, error_code);
  if (!file_chunk_store->Init(simulation_directory)) {
    LOG(kError) << "Failed to initialise file chunk store";
    return;
  }

  simulation_chunk_store_.reset(new ThreadsafeChunkStore(file_chunk_store));
  simulation_chunk_action_authority_.reset(
      new chunk_actions::ChunkActionAuthority(simulation_chunk_store_));
}

LocalChunkManager::~LocalChunkManager() {}

void LocalChunkManager::GetChunk(const ChunkId& name,
                                 const ChunkVersion& local_version,
                                 const asymm::Keys& keys,
                                 bool lock) {
  if (get_wait_.total_milliseconds() != 0) {
    Sleep(get_wait_);
  }
  // TODO(Team): Add check of ID on network
  if (chunk_store_->Has(name)) {
    (*sig_chunk_got_)(name, kSuccess);
    return;
  }
  if (lock && local_version.IsInitialised() &&
      simulation_chunk_action_authority_->Version(name) == local_version) {
    LOG(kWarning) << "GetChunk - "
                  << (!keys.identity.string().empty() ? DebugId(keys.identity) : "Anonymous")
                  << " - Won't retrieve " << Base32Substr(name)
                  << " because local and remote versions "
                  << HexSubstr(local_version) << " match.";
    (*sig_chunk_got_)(name, kChunkNotModified);
    return;
  }
  std::string content, existing_lock, transaction_id;
  fs::path lock_file = lock_directory_ / EncodeToBase32(name);
  boost::system::error_code error_code;
  if (lock) {
    while (fs::exists(lock_file, error_code)) {
      LOG(kInfo) << "GetChunk - Before Get, lock file exists for " << Base32Substr(name);
      ReadFile(lock_file, &existing_lock);
      std::string lock_timestamp_string(existing_lock.substr(0, existing_lock.find_first_of(' ')));
      uint32_t lock_timestamp(boost::lexical_cast<uint32_t>(lock_timestamp_string));
      uint32_t current_timestamp(GetTimeStamp());
      if (current_timestamp > lock_timestamp + lock_timeout_.count())
        break;
      else
        Sleep(boost::posix_time::seconds(1));
    }
    uint32_t current_time(GetTimeStamp());
    transaction_id = RandomAlphaNumericString(32);
    std::string current_time_string(boost::lexical_cast<std::string>(current_time));
    std::string lock_content(current_time_string + " " + transaction_id);
    WriteFile(lock_file, lock_content);
    current_transactions_[name] = transaction_id;
    LOG(kInfo) << "Wrote lock file for " << Base32Substr(name);
  }
  content = simulation_chunk_action_authority_->Get(name,
                                                    ChunkVersion(),
                                                    keys.public_key);
  if (content.empty()) {
    LOG(kError) << "CAA failure on network chunkstore " << Base32Substr(name);
    (*sig_chunk_got_)(name, kGetFailure);
    return;
  }

  if (!chunk_store_->Store(name, content)) {
    LOG(kError) << "Failed to store locally " << Base32Substr(name);
    (*sig_chunk_got_)(name, kGetFailure);
    return;
  }

  (*sig_chunk_got_)(name, kSuccess);
}

void LocalChunkManager::StoreChunk(const ChunkId& name, const asymm::Keys& keys) {
  if (get_wait_.total_milliseconds() != 0) {
    Sleep(action_wait_);
  }
  bool is_cacheable(simulation_chunk_action_authority_->Cacheable(name));
  // TODO(Team): Add check of ID on network
  std::string content(chunk_store_->Get(name));
  if (content.empty()) {
    LOG(kError) << "No chunk in local chunk store " << Base32Substr(name);
    (*sig_chunk_stored_)(name, kStoreFailure);
    return;
  }
  asymm::PublicKey public_key;
  if (!is_cacheable)
    public_key = keys.public_key;
  if (!simulation_chunk_action_authority_->Store(name,
                                                 content,
                                                 public_key)) {
    LOG(kError) << "CAA failure on network chunkstore " << Base32Substr(name);
    (*sig_chunk_stored_)(name, kStoreFailure);
    return;
  }

  (*sig_chunk_stored_)(name, kSuccess);
}

void LocalChunkManager::DeleteChunk(const ChunkId& name, const asymm::Keys& keys) {
  if (get_wait_.total_milliseconds() != 0) {
    Sleep(action_wait_);
  }

  bool is_cacheable(simulation_chunk_action_authority_->Cacheable(name));

  // TODO(Team): Add check of ID on network
  priv::chunk_actions::SignedData ownership_proof;
  std::string ownership_proof_string;
  asymm::PublicKey public_key;
  if (!is_cacheable) {
    ownership_proof.set_data(RandomString(16));
    std::string* signature(ownership_proof.mutable_signature());
    *signature = asymm::Sign(asymm::PlainText(ownership_proof.data()), keys.private_key).string();
    ownership_proof.SerializeToString(&ownership_proof_string);
    public_key = keys.public_key;
  }
  if (!simulation_chunk_action_authority_->Delete(name, ownership_proof_string, public_key)) {
    LOG(kError) << "CAA failure on network chunkstore " << Base32Substr(name);
    (*sig_chunk_deleted_)(name, kDeleteFailure);
    return;
  }

  (*sig_chunk_deleted_)(name, kSuccess);
}

void LocalChunkManager::ModifyChunk(const ChunkId& name,
                                    const std::string& content,
                                    const asymm::Keys& keys) {
  if (get_wait_.total_milliseconds() != 0) {
    Sleep(action_wait_);
  }
  fs::path lock_file = lock_directory_ / EncodeToBase32(name);
  boost::system::error_code error_code;
  if (fs::exists(lock_file, error_code)) {
    std::string existing_lock;
    LOG(kInfo) << "GetChunk - Modify, lock file exists for " << Base32Substr(name);
    std::string expected_transaction_id(current_transactions_[name]);
    ReadFile(lock_file, &existing_lock);
    std::string lock_transaction_id(
        existing_lock.substr(existing_lock.find_first_of(' ') + 1));
    if (lock_transaction_id == expected_transaction_id) {
      fs::remove(lock_file, error_code);
    LOG(kInfo) << "Removed lock file for " << Base32Substr(name);
    }
  }

  int64_t operation_diff;
  if (!simulation_chunk_action_authority_->Modify(name,
                                                  content,
                                                  keys.public_key,
                                                  &operation_diff)) {
    LOG(kError) << "CAA failure on network chunkstore " << Base32Substr(name);
    (*sig_chunk_modified_)(name, kModifyFailure);
    return;
  }

  (*sig_chunk_modified_)(name, kSuccess);
}

int64_t LocalChunkManager::StorageSize() {
  return simulation_chunk_store_->Size();
}

int64_t LocalChunkManager::StorageCapacity() {
  return simulation_chunk_store_->Capacity();
}

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
