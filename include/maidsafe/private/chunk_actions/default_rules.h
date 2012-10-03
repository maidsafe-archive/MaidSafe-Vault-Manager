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

#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/chunk_actions/chunk_type.h"


namespace maidsafe {

namespace priv {

namespace chunk_store { class ChunkStore; }

namespace chunk_actions {

namespace detail {

template <ChunkType chunk_type>
bool IsCacheable();

template <ChunkType chunk_type>
bool IsModifiable();

template <ChunkType chunk_type>
bool DoesModifyReplace();

template <ChunkType chunk_type>
bool IsPayable();

template <ChunkType chunk_type>
bool IsValidChunk(const ChunkId& name, std::shared_ptr<chunk_store::ChunkStore> chunk_store);

template <ChunkType chunk_type>
std::string GetVersion(const ChunkId& name, std::shared_ptr<chunk_store::ChunkStore> chunk_store);

template <ChunkType chunk_type>
int ProcessGet(const ChunkId& name,
               const std::string& version,
               const asymm::PublicKey& public_key,
               std::string* existing_content,
               std::shared_ptr<chunk_store::ChunkStore> chunk_store);

template <ChunkType chunk_type>
int ProcessStore(const ChunkId& name,
                 const std::string& content,
                 const asymm::PublicKey& public_key,
                 std::shared_ptr<chunk_store::ChunkStore> chunk_store);

template <ChunkType chunk_type>
int ProcessDelete(const ChunkId& name,
                  const std::string& ownership_proof,
                  const asymm::PublicKey& public_key,
                  std::shared_ptr<chunk_store::ChunkStore> chunk_store);

template <ChunkType chunk_type>
int ProcessModify(const ChunkId& name,
                  const std::string& content,
                  const asymm::PublicKey& public_key,
                  int64_t* size_difference,
                  std::string* new_content,
                  std::shared_ptr<chunk_store::ChunkStore> chunk_store);

template <ChunkType chunk_type>
int ProcessHas(const ChunkId& name,
               const std::string& version,
               const asymm::PublicKey& public_key,
               std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Returns true.
template <>
bool IsCacheable<ChunkType::kDefault>();

// Returns false.
template <>
bool IsModifiable<ChunkType::kDefault>();

// Returns false.
template <>
bool DoesModifyReplace<ChunkType::kDefault>();

// Returns true.
template <>
bool IsPayable<ChunkType::kDefault>();

// Returns true if the chunk exists, and name == Hash(content).
template <>
bool IsValidChunk<ChunkType::kDefault>(const ChunkId& name,
                                       std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Returns first 24 bytes of name.
template <>
std::string GetVersion<ChunkType::kDefault>(const ChunkId& name,
                                            std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Any user can Get.
// For overall success, the following must be true:
//   * chunk_store.get() succeeds
// NB - version is not used in this function.
template <>
int ProcessGet<ChunkType::kDefault>(const ChunkId& name,
                                    const std::string& version,
                                    const asymm::PublicKey& public_key,
                                    std::string* existing_content,
                                    std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Any user can Store.
// For overall success, the following must be true:
//   * public_key is valid
//   * if the chunk exsist already, content must match existing content,
//     otherwise name must match Hash(content)
// This assumes that public_key has not been revoked on the network.
template <>
int ProcessStore<ChunkType::kDefault>(const ChunkId& name,
                                      const std::string& content,
                                      const asymm::PublicKey& public_key,
                                      std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Any user can Delete.
// Always returns kSuccess.
// This assumes that owner of public_key has already been confirmed as being
// a valid Chunk Info Holder, and that public_key has not been revoked on the
// network.
template <>
int ProcessDelete<ChunkType::kDefault>(const ChunkId& name,
                                       const std::string& ownership_proof,
                                       const asymm::PublicKey& public_key,
                                       std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Modify is an invalid operation for all users.
template <>
int ProcessModify<ChunkType::kDefault>(const ChunkId& name,
                                       const std::string& content,
                                       const asymm::PublicKey& public_key,
                                       int64_t* size_difference,
                                       std::string* new_content,
                                       std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Any user can call Has.
// For overall success, the following must be true:
//   * chunk_store.has() succeeds
// NB - version is not used in this function.
template <>
int ProcessHas<ChunkType::kDefault>(const ChunkId& name,
                                    const std::string& version,
                                    const asymm::PublicKey& public_key,
                                    std::shared_ptr<chunk_store::ChunkStore> chunk_store);

}  // namespace detail

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_DEFAULT_RULES_H_
