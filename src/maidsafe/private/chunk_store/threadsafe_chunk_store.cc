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

#include "maidsafe/private/chunk_store/threadsafe_chunk_store.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_store {

ThreadsafeChunkStore::ThreadsafeChunkStore(
    std::shared_ptr<ChunkStore> chunk_store)
        : ChunkStore(),
          chunk_store_(chunk_store),
          mutex_() {}

ThreadsafeChunkStore::~ThreadsafeChunkStore() {}

std::string ThreadsafeChunkStore::Get(const std::string &name) const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Get(name);
}

bool ThreadsafeChunkStore::Get(const std::string &name,
                               const fs::path &sink_file_name) const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Get(name, sink_file_name);
}

bool ThreadsafeChunkStore::Store(const std::string &name,
                                 const std::string &content) {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Store(name, content);
}

bool ThreadsafeChunkStore::Store(const std::string &name,
                                 const fs::path &source_file_name,
                                 bool delete_source_file) {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Store(name, source_file_name, delete_source_file);
}

bool ThreadsafeChunkStore::Delete(const std::string &name) {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Delete(name);
}

bool ThreadsafeChunkStore::Modify(const std::string &name,
                                  const std::string &content) {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Modify(name, content);
}

bool ThreadsafeChunkStore::Modify(const std::string &name,
                                  const fs::path &source_file_name,
                                  bool delete_source_file) {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Modify(name, source_file_name, delete_source_file);
}

bool ThreadsafeChunkStore::Has(const std::string &name) const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Has(name);
}

bool ThreadsafeChunkStore::MoveTo(const std::string &name,
                                  ChunkStore *sink_chunk_store) {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->MoveTo(name, sink_chunk_store);
}

uintmax_t ThreadsafeChunkStore::Size(const std::string &name) const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Size(name);
}

uintmax_t ThreadsafeChunkStore::Size() const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Size();
}

uintmax_t ThreadsafeChunkStore::Capacity() const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Capacity();
}

void ThreadsafeChunkStore::SetCapacity(const uintmax_t &capacity) {
  boost::lock_guard<boost::mutex> lock(mutex_);
  chunk_store_->SetCapacity(capacity);
}

bool ThreadsafeChunkStore::Vacant(const uintmax_t &required_size) const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Vacant(required_size);
}

uintmax_t ThreadsafeChunkStore::Count(const std::string &name) const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Count(name);
}

uintmax_t ThreadsafeChunkStore::Count() const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Count();
}

bool ThreadsafeChunkStore::Empty() const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->Empty();
}

void ThreadsafeChunkStore::Clear() {
  boost::lock_guard<boost::mutex> lock(mutex_);
  chunk_store_->Clear();
}

std::vector<ChunkData> ThreadsafeChunkStore::GetChunks() const {
  boost::lock_guard<boost::mutex> lock(mutex_);
  return chunk_store_->GetChunks();
}

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
