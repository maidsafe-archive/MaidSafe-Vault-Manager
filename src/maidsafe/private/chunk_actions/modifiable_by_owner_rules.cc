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

#include "maidsafe/private/chunk_actions/modifiable_by_owner_rules.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/utils.h"

#include "maidsafe/private/chunk_store/chunk_store.h"


namespace maidsafe {

namespace priv {

namespace chunk_actions {

namespace detail {

template <>
bool IsCacheable<ChunkType::kModifiableByOwner>() { return false; }

template <>
bool IsModifiable<ChunkType::kModifiableByOwner>() { return true; }

template <>
bool DoesModifyReplace<ChunkType::kModifiableByOwner>() { return true; }

template <>
bool IsPayable<ChunkType::kModifiableByOwner>() { return false; }

template <>
bool IsValidChunk<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  // TODO(Fraser#5#): 2011-12-17 - Check this is all that's needed here
  std::string existing_data(chunk_store->Get(name));
  if (existing_data.empty()) {
    LOG(kError) << "Failed to get " << Base32Substr(name) << " for validation";
    return false;
  }
  return true;
}

template <>
ChunkVersion GetVersion<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  std::string chunk_content;
  ChunkVersion version;
  GetContentAndTigerHash(name, chunk_store, chunk_content, version);
  return version;
}

template <>
int ProcessGet<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    const ChunkVersion& version,
    const asymm::PublicKey& /*public_key*/,
    std::string* existing_content,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  if (!version.IsInitialised()) {
    *existing_content = chunk_store->Get(name);
    if (existing_content->empty()) {
      LOG(kError) << "Failed to get " << Base32Substr(name);
      return kFailedToFindChunk;
    }
  } else {
    ChunkVersion existing_version;
    GetContentAndTigerHash(name, chunk_store, *existing_content, existing_version);
    if (version != existing_version) {
      LOG(kError) << "Failed to get requested version of " << Base32Substr(name);
      return kDifferentVersion;
    }
  }

  return kSuccess;
}

template <>
int ProcessStore<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    const std::string& content,
    const asymm::PublicKey& public_key,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  if (chunk_store->Has(name)) {
    LOG(kWarning) << "Failed to store " << Base32Substr(name) << ": chunk already exists";
    return kKeyNotUnique;
  }

  SignedData chunk;
  if (!ParseProtobuf<SignedData>(content, &chunk)) {
    LOG(kError) << "Failed to store " << Base32Substr(name) << ": data doesn't parse as a chunk";
    return kInvalidSignedData;
  }

  bool valid(false);
  try {
    valid = asymm::CheckSignature(asymm::PlainText(chunk.data()),
                                  asymm::Signature(chunk.signature()),
                                  public_key);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kSignatureCheckError;
  }

  if (!valid) {
    LOG(kError) << "Failed to store " << Base32Substr(name) << ": signature verification failed";
    return kFailedSignatureCheck;
  }

  return kSuccess;
}

template <>
int ProcessDelete<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    const std::string& ownership_proof,
    const asymm::PublicKey& public_key,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  std::string existing_content = chunk_store->Get(name);
  if (existing_content.empty()) {
    LOG(kInfo) << Base32Substr(name) << " already deleted";
    return kSuccess;
  }

  SignedData existing_chunk;
  if (!ParseProtobuf<SignedData>(existing_content, &existing_chunk)) {
    LOG(kError) << "Failed to delete " << Base32Substr(name)
                << ": existing data doesn't parse";
    return kParseFailure;
  }

  bool valid(false);
  try {
    valid = asymm::CheckSignature(asymm::PlainText(existing_chunk.data()),
                                  asymm::Signature(existing_chunk.signature()),
                                  public_key);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kSignatureCheckError;
  }

  if (!valid) {
    LOG(kError) << "Failed to delete " << Base32Substr(name) << ": signature verification failed";
    return kFailedSignatureCheck;
  }

  SignedData deletion_token;
  if (!ParseProtobuf<SignedData>(ownership_proof, &deletion_token)) {
    LOG(kError) << "Failed to delete " << Base32Substr(name)
                << ": deletion_token doesn't parse - not owner";
    return kNotOwner;
  }

  try {
    valid = asymm::CheckSignature(asymm::PlainText(deletion_token.data()),
                                  asymm::Signature(deletion_token.signature()),
                                  public_key);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kSignatureCheckError;
  }

  if (!valid) {
    LOG(kError) << "Failed to delete " << Base32Substr(name)
                << ": signature verification failed - not owner";
    return kNotOwner;
  }

  return kSuccess;
}

template <>
int ProcessModify<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    const std::string& content,
    const asymm::PublicKey& public_key,
    int64_t* size_difference,
    std::string* new_content,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  new_content->clear();
  std::string existing_content = chunk_store->Get(name);
  if (existing_content.empty()) {
    LOG(kError) << Base32Substr(name) << " doesn't exist";
    return kFailedToFindChunk;
  }

  SignedData existing_chunk;
  if (!ParseProtobuf<SignedData>(existing_content, &existing_chunk)) {
    LOG(kError) << "Failed to modify " << Base32Substr(name)
                << ": existing data doesn't parse as SignedData";
    return kParseFailure;
  }

  bool valid(false);
  try {
    valid = asymm::CheckSignature(asymm::PlainText(existing_chunk.data()),
                                  asymm::Signature(existing_chunk.signature()),
                                  public_key);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kSignatureCheckError;
  }

  if (!valid) {
    LOG(kError) << "Failed to modify " << Base32Substr(name) << ": not owner";
    return kNotOwner;
  }

  SignedData new_chunk;
  if (!ParseProtobuf<SignedData>(content, &new_chunk)) {
    LOG(kError) << "Failed to modify " << Base32Substr(name)
                << ": new data doesn't parse as SignedData";
    return kInvalidSignedData;
  }

  try {
    valid = asymm::CheckSignature(asymm::PlainText(new_chunk.data()),
                                  asymm::Signature(new_chunk.signature()),
                                  public_key);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kSignatureCheckError;
  }

  if (!valid) {
    LOG(kError) << "Failed to modify " << Base32Substr(name) << ": signature verification failed";
    return kFailedSignatureCheck;
  }

  *size_difference = static_cast<int64_t>(existing_content.size()) - content.size();
  *new_content = content;
  return kSuccess;
}

template <>
int ProcessHas<ChunkType::kModifiableByOwner>(
    const ChunkId& name,
    const ChunkVersion& version,
    const asymm::PublicKey& /*public_key*/,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  if (!version.IsInitialised()) {
    if (!chunk_store->Has(name)) {
      LOG(kError) << "Failed to find " << Base32Substr(name);
      return kFailedToFindChunk;
    }
  } else {
    std::string existing_content;
    ChunkVersion existing_version;
    GetContentAndTigerHash(name, chunk_store, existing_content, existing_version);
    if (version != existing_version) {
      LOG(kError) << "Failed to find requested version of " << Base32Substr(name);
      return kDifferentVersion;
    }
  }

  return kSuccess;
}

}  // namespace detail

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe
