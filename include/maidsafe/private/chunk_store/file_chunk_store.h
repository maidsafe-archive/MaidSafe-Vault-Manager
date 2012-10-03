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

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_FILE_CHUNK_STORE_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_FILE_CHUNK_STORE_H_

#include <string>
#include <utility>
#include <vector>

#ifdef __MSVC__
#  pragma warning(push, 1)
#  pragma warning(disable: 4127 4250)
#endif

#include "boost/filesystem/path.hpp"
#include "boost/filesystem/fstream.hpp"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "maidsafe/private/chunk_store/chunk_store.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_store {

namespace test { class FileChunkStoreTest_BEH_Methods_Test; }

class FileChunkStore : public ChunkStore {
 public:
  FileChunkStore();
  ~FileChunkStore();
  // Initialises the chunk storage directory.  If the given directory path does not exist, it will
  // be created.  Returns true if directory exists or could be created.
  bool Init(const fs::path& storage_location, unsigned int dir_depth = 5U);
  std::string Get(const ChunkId& name) const;
  bool Get(const ChunkId& name, const fs::path& sink_file_name) const;
  bool Store(const ChunkId& name, const std::string& content);
  bool Store(const ChunkId& name, const fs::path& source_file_name, bool delete_source_file);
  bool Delete(const ChunkId& name);
  bool Modify(const ChunkId& name, const std::string& content);
  bool Modify(const ChunkId& name, const fs::path& source_file_name, bool delete_source_file);
  bool Has(const ChunkId& name) const;
  bool MoveTo(const ChunkId& name, ChunkStore* sink_chunk_store);
  uintmax_t Size(const ChunkId& name) const;
  uintmax_t Size() const { return ChunkStore::Size(); }
  uintmax_t Capacity() const;
  void SetCapacity(const uintmax_t& capacity);
  bool Vacant(const uintmax_t& required_size) const;
  uintmax_t Count(const ChunkId& name) const;
  uintmax_t Count() const;
  bool Empty() const;
  void Clear();
  std::vector<ChunkData> GetChunks() const;
  friend class test::FileChunkStoreTest_BEH_Methods_Test;

 private:
  typedef std::pair<uintmax_t, uintmax_t> RestoredChunkStoreInfo;

  FileChunkStore(const FileChunkStore&);
  FileChunkStore& operator=(const FileChunkStore&);

  // Generates sub-dirs based on chunk-name and dir_depth_ specified.  Returns the absolute file
  // path after encoding the chunk name to base 32.
  fs::path ChunkNameToFilePath(const ChunkId& name, bool generate_dirs = false) const;
  void IncreaseChunkCount() { ++chunk_count_; }
  void DecreaseChunkCount() { --chunk_count_; }
  void ChunkAdded(const uintmax_t& delta);
  void ChunkRemoved(const uintmax_t& delta);
  void ResetChunkCount(uintmax_t chunk_count = 0) { chunk_count_ = chunk_count; }
  // Tries to read the ChunkStore info file in dir specified and gets total number of chunks and
  // their collective size
  RestoredChunkStoreInfo RetrieveChunkInfo(const fs::path& location) const;
  // Saves the current state of the ChunkStore (in terms of total number of chunks and their
  // collective size) to the info file
  void SaveChunkStoreState();
  bool IsChunkStoreInitialised() const { return initialised_; }
  uintmax_t GetChunkReferenceCount(const fs::path& chunk_path) const;
  uintmax_t SpaceAvailable() const;
  static std::string InfoFileName() { return "info"; }

  bool initialised_;
  fs::path storage_location_;
  uintmax_t chunk_count_;
  unsigned int dir_depth_;
  fs::fstream info_file_;
};

}  //  namespace chunk_store

}  //  namespace priv

}  //  namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_FILE_CHUNK_STORE_H_
