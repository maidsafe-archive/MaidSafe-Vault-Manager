/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file licence.txt found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

// Applies to self-encrypted file chunks

#ifndef MAIDSAFE_PRIVATE_CHUNK_ACTIONS_DEFAULT_RULES_H_
#define MAIDSAFE_PRIVATE_CHUNK_ACTIONS_DEFAULT_RULES_H_

#include <memory>
#include <string>

#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_actions/utils.h"


namespace maidsafe {

class ChunkStore;


namespace priv {

namespace chunk_actions {

template <>
bool IsCacheable<kDefaultType>() { return true; }

// Returns true if the chunk exists, and name == Hash(chunk.data()).
template <>
bool IsValidChunk<kDefaultType>(const std::string &name,
                                std::shared_ptr<ChunkStore> chunk_store);

// Any user can Get.
// For overall success, the following must be true:
//   * chunk_store.get() succeeds.
template <>
int ProcessGet<kDefaultType>(const std::string &name,
                             const std::string &version,
                             const asymm::PublicKey &public_key,
                             std::string *existing_content,
                             std::shared_ptr<ChunkStore> chunk_store);

// Any user can Store.
// For overall success, the following must be true:
//   * content parses as a chunk
//   * public_key is valid
//   * chunk.signature() validates with public_key
//   * if the chunk exsist already, chunk.data() must match existing.data()
//     otherwise name must match Hash(chunk.data()).
// This assumes that public_key has not been revoked on the network.
template <>
int ProcessStore<kDefaultType>(const std::string &name,
                               const std::string &content,
                               const asymm::PublicKey &public_key,
                               std::shared_ptr<ChunkStore> chunk_store);

// Any user can Delete.
// Always returns kSuccess.
// This assumes that owner of public_key has already been confirmed as being
// a valid Chunk Info Holder, and that public_key has not been revoked on the
// network.
template <>
int ProcessDelete<kDefaultType>(const std::string &name,
                                const std::string &version,
                                const asymm::PublicKey &public_key,
                                std::shared_ptr<ChunkStore> chunk_store);

// Modify is an invalid operation for all users.
template <>
int ProcessModify<kDefaultType>(const std::string &name,
                                const std::string &content,
                                const std::string &version,
                                const asymm::PublicKey &public_key,
                                std::string *new_content,
                                std::shared_ptr<ChunkStore> chunk_store);

// Any user can call Has.
// For overall success, the following must be true:
//   * chunk_store.has() succeeds.
template <>
int ProcessHas<kDefaultType>(const std::string &name,
                             const std::string &version,
                             const asymm::PublicKey &public_key,
                             std::shared_ptr<ChunkStore> chunk_store);

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_DEFAULT_RULES_H_
