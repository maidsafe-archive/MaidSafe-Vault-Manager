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

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_LOCAL_CHUNK_MANAGER_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_LOCAL_CHUNK_MANAGER_H_

#include <memory>
#include <string>
#include <map>

#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/private/chunk_store/chunk_manager.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_actions { class ChunkActionAuthority; }

namespace chunk_store {

class ChunkStore;

class LocalChunkManager : public ChunkManager {
 public:
  LocalChunkManager(std::shared_ptr<ChunkStore> normal_local_chunk_store,
                    const fs::path& simulation_directory,
                    const fs::path& lock_directory,
                    const boost::posix_time::time_duration& millisecs =
                        boost::posix_time::milliseconds(0));
  ~LocalChunkManager();

  void GetChunk(const ChunkId& name,
                const ChunkVersion& local_version,
                const Fob& fob,
                bool lock,
                bool try_cache);
  void StoreChunk(const ChunkId& name, const Fob& fob);
  void DeleteChunk(const ChunkId& name, const Fob& fob);
  void ModifyChunk(const ChunkId& name, const NonEmptyString& content, const Fob& fob);

  int64_t StorageSize();
  int64_t StorageCapacity();

 private:
  LocalChunkManager(const LocalChunkManager&);
  LocalChunkManager& operator=(const LocalChunkManager&);

  std::shared_ptr<ChunkStore> simulation_chunk_store_;
  std::shared_ptr<chunk_actions::ChunkActionAuthority> simulation_chunk_action_authority_;
  boost::posix_time::time_duration get_wait_, action_wait_;
  fs::path lock_directory_;
  std::map<ChunkId, std::string> current_transactions_;
};

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_LOCAL_CHUNK_MANAGER_H_
