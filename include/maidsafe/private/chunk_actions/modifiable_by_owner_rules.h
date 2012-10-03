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

// Applies to MID, SMID, TMID, STMID and encrypted Directory Listing DataMaps

#ifndef MAIDSAFE_PRIVATE_CHUNK_ACTIONS_MODIFIABLE_BY_OWNER_RULES_H_
#define MAIDSAFE_PRIVATE_CHUNK_ACTIONS_MODIFIABLE_BY_OWNER_RULES_H_

#include <memory>
#include <string>

#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_actions/chunk_type.h"
#include "maidsafe/private/chunk_actions/default_rules.h"


namespace maidsafe {

namespace priv {

namespace chunk_store { class ChunkStore; }

namespace chunk_actions {

namespace detail {

// Returns false.
template <>
bool IsCacheable<ChunkType::kModifiableByOwner>();

// Returns true.
template <>
bool IsModifiable<ChunkType::kModifiableByOwner>();

// Returns true.
template <>
bool DoesModifyReplace<ChunkType::kModifiableByOwner>();

// Returns false.
template <>
bool IsPayable<ChunkType::kModifiableByOwner>();

// Returns true if the chunk exists.
template <>
bool IsValidChunk<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Returns Tiger hash of chunk content.
template <>
std::string GetVersion<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Any user can Get.
// For overall success, the following must be true:
//   * chunk_store.get() succeeds
//   * if version is not an empty string, retrieved chunk's version must be
//     identical to this
template <>
int ProcessGet<ChunkType::kModifiableByOwner>(const ChunkId& name,
                                              const std::string& version,
                                              const asymm::PublicKey& public_key,
                                              std::string* existing_content,
                                              std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Any user can Store.
// For overall success, the following must be true:
//   * the chunk doesn't already exist
//   * content parses as SignedData
//   * public_key is valid
//   * chunk.signature() validates with public_key
// This assumes that public_key has not been revoked on the network.
template <>
int ProcessStore<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    const std::string& content,
    const asymm::PublicKey& public_key,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Only owner can Delete.
// For overall success, the following must be true:
//   * the chunk doesn't already exist
//                OR
//   * chunk_store.get() succeeds
//   * public_key is valid
//   * retrieved chunk.signature() validates with public_key
//   * deletion_token validates with public_key
// This assumes that public_key has not been revoked on the network.
template <>
int ProcessDelete<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    const std::string& ownership_proof,
    const asymm::PublicKey& public_key,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Only owner can Modify.
// For overall success, the following must be true:
//   * chunk_store.get() succeeds
//   * retrieved content parses as SignedData
//   * public_key is valid
//   * retrieved chunk.signature() validates with public_key
//   * content parses as SignedData
//   * new chunk.signature() validates with public_key
// This assumes that public_key has not been revoked on the network.
template <>
int ProcessModify<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    const std::string& content,
    const asymm::PublicKey& public_key,
    int64_t* size_difference,
    std::string* new_content,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store);

// Any user can call Has.
// For overall success, the following must be true:
//   * chunk_store.has() succeeds
//   * if version is not an empty string, retrieved chunk's version must be
//     identical to this
template <>
int ProcessHas<ChunkType::kModifiableByOwner>(const ChunkId& name,
                                              const std::string& version,
                                              const asymm::PublicKey& public_key,
                                              std::shared_ptr<chunk_store::ChunkStore> chunk_store);

}  // namespace detail

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_MODIFIABLE_BY_OWNER_RULES_H_
