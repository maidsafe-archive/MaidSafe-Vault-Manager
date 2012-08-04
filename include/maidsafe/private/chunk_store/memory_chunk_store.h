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

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_MEMORY_CHUNK_STORE_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_MEMORY_CHUNK_STORE_H_

#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4127)
#endif

#include "boost/filesystem/path.hpp"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/private/chunk_store/chunk_store.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_store {

class MemoryChunkStore : public ChunkStore {
 public:
  MemoryChunkStore();
  ~MemoryChunkStore();
  std::string Get(const std::string &name) const;
  bool Get(const std::string &name, const fs::path &sink_file_name) const;
  bool Store(const std::string &name, const std::string &content);
  bool Store(const std::string &name,
             const fs::path &source_file_name,
             bool delete_source_file);
  bool Delete(const std::string &name);
  bool Modify(const std::string &name, const std::string &content);
  bool Modify(const std::string &name,
              const fs::path &source_file_name,
              bool delete_source_file);
  bool Has(const std::string &name) const;
  bool MoveTo(const std::string &name, ChunkStore *sink_chunk_store);
  uintmax_t Size(const std::string &name) const;
  uintmax_t Size() const { return ChunkStore::Size(); }
  uintmax_t Count(const std::string &name) const;
  uintmax_t Count() const;
  bool Empty() const;
  void Clear();
  std::vector<ChunkData> GetChunks() const;

 private:
  typedef std::pair<uintmax_t, std::string> ChunkEntry;
  MemoryChunkStore(const MemoryChunkStore&);
  MemoryChunkStore& operator=(const MemoryChunkStore&);
  std::map<std::string, ChunkEntry> chunks_;
};

}  //  namespace chunk_store

}  //  namespace priv

}  //  namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_MEMORY_CHUNK_STORE_H_
