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

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_BUFFERED_CHUNK_STORE_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_BUFFERED_CHUNK_STORE_H_

#include <functional>
#include <list>
#include <set>
#include <string>
#include <memory>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4127)
#endif

#include "boost/asio/io_service.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/condition_variable.hpp"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/private/chunk_store/chunk_store.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_store {

class FileChunkStore;
class MemoryChunkStore;
class ThreadsafeChunkStore;

// Manages storage and retrieval of chunks using a two-tier storage system.
class BufferedChunkStore : public ChunkStore {
 public:
  explicit BufferedChunkStore(boost::asio::io_service &asio_service);  // NOLINT (Dan)
  ~BufferedChunkStore();

  // Initialises the chunk storage directory.  If the given directory path does
  // not exist, it will be created.  Returns true if directory exists or could
  // be created.
  bool Init(const fs::path &storage_location,
            std::list<std::string> removable_chunks = std::list<std::string>(),
            unsigned int dir_depth = 5U);

  std::string Get(const std::string &name) const;

  bool Get(const std::string &name, const fs::path &sink_file_name) const;

  // This method returns once the chunk is stored in the cache. It will then be
  // asynchronously written to the file-based permanent store.
  bool Store(const std::string &name, const std::string &content);

  // This method returns once the chunk is stored in the cache. It will then be
  // asynchronously written to the file-based permanent store.
  bool Store(const std::string &name,
             const fs::path &source_file_name,
             bool delete_source_file);

  // Stores chunk content under the given name in cache.
  bool CacheStore(const std::string &name, const std::string &content);

  // Stores chunk content under the given name in cache.
  bool CacheStore(const std::string &name,
                  const fs::path &source_file_name,
                  bool delete_source_file);

  // Stores an already cached chunk in the permanent store (blocking).
  bool PermanentStore(const std::string &name);

  bool Delete(const std::string &name);

  bool Modify(const std::string &name, const std::string &content);

  bool Modify(const std::string &name,
              const fs::path &source_file_name,
              bool delete_source_file);

  bool Has(const std::string &name) const;

  bool MoveTo(const std::string &name, ChunkStore *sink_chunk_store);

  // Checks if a chunk exists in cache.
  bool CacheHas(const std::string &name) const;

  // Checks if a chunk exists in permanent store.
  bool PermanentHas(const std::string &name) const;

  uintmax_t Size(const std::string &name) const;

  uintmax_t Size() const;

  // Retrieves the total size of the cached chunks.
  uintmax_t CacheSize() const;

  // Retrieves the maximum permanent storage capacity in bytes available.  A
  // capacity of zero (0) equals infinite storage space.
  uintmax_t Capacity() const;

  // Retrieves the maximum cache capacity in bytes available.  A capacity of
  // zero (0) equals infinite storage space.
  uintmax_t CacheCapacity() const;

  // Sets the maximum permanent storage capacity in bytes available.  A capacity
  // of zero (0) equals infinite storage space. The capacity must always be at
  // least as high as the total size of already stored chunks.
  void SetCapacity(const uintmax_t &capacity);

  // Sets the maximum cache capacity in bytes available.  A capacity of zero (0)
  // equals infinite storage space. The capacity must always be at least as high
  // as the total size of already stored chunks.
  void SetCacheCapacity(const uintmax_t &capacity);

  // Checks whether the permanent storage has enough capacity to store a chunk
  // of the given size.
  bool Vacant(const uintmax_t &required_size) const;

  // Checks whether the cache has enough capacity to store a chunk of the given
  // size.
  bool CacheVacant(const uintmax_t &required_size) const;

  uintmax_t Count(const std::string &name) const;

  // Retrieves the number of chunks held by the permanent store.
  uintmax_t Count() const;

  // Retrieves the number of chunks held in cache.
  uintmax_t CacheCount() const;

  // Checks if any chunks are held by this ChunkStore.
  bool Empty() const;

  // Checks if any chunks are held in cache.
  bool CacheEmpty() const;

  // Deletes all stored chunks.
  void Clear();

  // Deletes all cached chunks.
  void CacheClear();

  // Mark a chunk in the permanent store to be deleted in case there is not
  // enough space to store a new chunk.
  void MarkForDeletion(const std::string &name);

  bool DeleteAllMarked();

  std::list<std::string> GetRemovableChunks() const;

  std::vector<ChunkData> GetChunks() const;

 private:
  BufferedChunkStore(const BufferedChunkStore&);
  BufferedChunkStore& operator=(const BufferedChunkStore&);

  void AddCachedChunksEntry(const std::string &name) const;
  bool DoCacheStore(const std::string &name,
                    const std::string &content) const;
  bool DoCacheStore(const std::string &name,
                    const uintmax_t &size,
                    const fs::path &source_file_name,
                    bool delete_source_file) const;
  bool MakeChunkPermanent(const std::string &name, const uintmax_t &size);
  void DoMakeChunkPermanent(const std::string &name);
  void RemoveDeletionMarks(const std::string &name);

  mutable boost::mutex cache_mutex_, xfer_mutex_;
  mutable boost::condition_variable xfer_cond_var_;
  boost::asio::io_service &asio_service_;
  std::shared_ptr<FileChunkStore> internal_perm_chunk_store_;
  mutable std::shared_ptr<MemoryChunkStore> cache_chunk_store_;
  std::shared_ptr<ThreadsafeChunkStore> perm_chunk_store_;
  mutable std::list<std::string> cached_chunks_;
  std::list<std::string> removable_chunks_;
  std::multiset<std::string> pending_xfers_;
  uintmax_t perm_size_;
  bool initialised_;
};

}  //  namespace chunk_store

}  //  namespace priv

}  //  namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_BUFFERED_CHUNK_STORE_H_
