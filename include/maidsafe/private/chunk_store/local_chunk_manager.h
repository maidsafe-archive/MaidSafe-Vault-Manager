/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/


#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_LOCAL_CHUNK_MANAGER_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_LOCAL_CHUNK_MANAGER_H_

#include <memory>
#include <string>

#include "maidsafe/private/chunk_store/chunk_manager.h"

#include "maidsafe/private/version.h"
#if MAIDSAFE_PRIVATE_VERSION != 200
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif


namespace maidsafe {

namespace priv {

namespace chunk_actions { class ChunkActionAuthority; }

namespace chunk_store {

class ChunkStore;

class LocalChunkManager : public ChunkManager {
 public:
  LocalChunkManager(std::shared_ptr<ChunkStore> normal_local_chunk_store,
                    const fs::path &simulation_directory);
  ~LocalChunkManager();

  void GetChunk(const std::string &name,
                const asymm::Identity &owner_key_id,
                const asymm::PublicKey &owner_public_key,
                const std::string &ownership_proof);
  void StoreChunk(const std::string &name,
                  const asymm::Identity &owner_key_id,
                  const asymm::PublicKey &owner_public_key);
  void DeleteChunk(const std::string &name,
                   const asymm::Identity &owner_key_id,
                   const asymm::PublicKey &owner_public_key,
                   const std::string &ownership_proof);
  void ModifyChunk(const std::string &name,
                   const std::string &content,
                   const asymm::Identity &owner_key_id,
                   const asymm::PublicKey &owner_public_key);

 private:
  LocalChunkManager(const LocalChunkManager&);
  LocalChunkManager& operator=(const LocalChunkManager&);

  std::shared_ptr<ChunkStore> simulation_chunk_store_;
  std::shared_ptr<chunk_actions::ChunkActionAuthority> simulation_chunk_action_authority_;  // NOLINT (Dan)
};

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_LOCAL_CHUNK_MANAGER_H_
