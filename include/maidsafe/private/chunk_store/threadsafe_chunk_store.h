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

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_THREADSAFE_CHUNK_STORE_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_THREADSAFE_CHUNK_STORE_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/private/chunk_store/chunk_store.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_store {

// Concrete threadsafe class to manage storage and retrieval of chunks.  The
// class implements shared mutex locking around another concrete ChunkStore.
class ThreadsafeChunkStore : public ChunkStore {
 public:
  explicit ThreadsafeChunkStore(std::shared_ptr<ChunkStore> chunk_store);
  ~ThreadsafeChunkStore();
  std::string Get(const ChunkId& name) const;
  bool Get(const ChunkId& name, const fs::path& sink_file_name) const;
  bool Store(const ChunkId& name, const std::string& content);
  bool Store(const ChunkId& name,
             const fs::path& source_file_name,
             bool delete_source_file);
  bool Delete(const ChunkId& name);
  bool Modify(const ChunkId& name, const std::string& content);
  bool Modify(const ChunkId& name,
              const fs::path& source_file_name,
              bool delete_source_file);
  bool Has(const ChunkId& name) const;
  bool MoveTo(const ChunkId& name, ChunkStore* sink_chunk_store);
  uintmax_t Size(const ChunkId& name) const;
  uintmax_t Size() const;
  uintmax_t Capacity() const;
  void SetCapacity(const uintmax_t& capacity);
  bool Vacant(const uintmax_t& required_size) const;
  uintmax_t Count(const ChunkId& name) const;
  uintmax_t Count() const;
  bool Empty() const;
  void Clear();
  std::vector<ChunkData> GetChunks() const;

 private:
  ThreadsafeChunkStore(const ThreadsafeChunkStore&);
  ThreadsafeChunkStore& operator=(const ThreadsafeChunkStore&);

  std::shared_ptr<ChunkStore> chunk_store_;
  mutable boost::mutex mutex_;
};

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_THREADSAFE_CHUNK_STORE_H_
