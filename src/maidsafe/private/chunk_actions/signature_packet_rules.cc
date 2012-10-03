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

#include "maidsafe/private/chunk_actions/signature_packet_rules.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/utils.h"

#include "maidsafe/private/chunk_store/chunk_store.h"

namespace maidsafe {

namespace priv {

namespace chunk_actions {

namespace detail {

const std::string kRevokedSignaturePacket("0");

template <>
bool IsCacheable<ChunkType::kSignaturePacket>() { return false; }

template <>
bool IsModifiable<ChunkType::kSignaturePacket>() { return false; }

template <>
bool DoesModifyReplace<ChunkType::kSignaturePacket>() { return false; }

template <>
bool IsPayable<ChunkType::kSignaturePacket>() { return false; }

template <>
bool IsValidChunk<ChunkType::kSignaturePacket>(
    const ChunkId& name,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  std::string existing_data(chunk_store->Get(name));
  if (existing_data.empty()) {
    LOG(kError) << "Failed to get " << Base32Substr(name) << " for validation";
    return false;
  }

  SignedData existing_chunk;
  if (!ParseProtobuf<SignedData>(existing_data, &existing_chunk)) {
    LOG(kError) << "Failed to validate " << Base32Substr(name)
                << ": existing data doesn't parse as a SignedData";
    return false;
  }

  if (crypto::Hash<crypto::SHA512>(existing_chunk.data() + existing_chunk.signature()).string() !=
      RemoveTypeFromName(name).string()) {
    LOG(kError) << "Failed to validate " << Base32Substr(name) << ": chunk isn't hashable";
    return false;
  }

  return true;
}

template <>
std::string GetVersion<ChunkType::kSignaturePacket>(
    const ChunkId& name,
    std::shared_ptr<chunk_store::ChunkStore> /*chunk_store*/) {
  return name.string().substr(0, crypto::Tiger::DIGESTSIZE);
}

template <>
int ProcessGet<ChunkType::kSignaturePacket>(const ChunkId& name,
                                            const std::string& /*version*/,
                                            const asymm::PublicKey& /*public_key*/,
                                            std::string* existing_content,
                                            std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  *existing_content = chunk_store->Get(name);
  if (existing_content->empty()) {
    LOG(kError) << "Failed to get " << Base32Substr(name);
    return kFailedToFindChunk;
  }

  return kSuccess;
}

template <>
int ProcessStore<ChunkType::kSignaturePacket>(
    const ChunkId& name,
    const std::string& content,
    const asymm::PublicKey& public_key,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  if (chunk_store->Has(name)) {
    LOG(kError) << "Failed to store " << Base32Substr(name) << ": chunk already exists";
    return kKeyNotUnique;
  }

  SignedData chunk;
  if (!ParseProtobuf<SignedData>(content, &chunk)) {
    LOG(kError) << "Failed to store " << Base32Substr(name) << ": data doesn't parse as a SignedData";
    return kInvalidSignedData;
  }

  try {
    asymm::PublicKey decoded_public_key(asymm::DecodeKey(asymm::EncodedPublicKey(chunk.data())));
    asymm::PublicKey validating_key;
                                                                                                  static_cast<void>(public_key);
                                                                                                  //if (asymm::ValidateKey(public_key))
                                                                                                  //  validating_key = public_key;
                                                                                                  //else
                                                                                                  //  validating_key = decoded_public_key;
    if (!asymm::CheckSignature(asymm::PlainText(chunk.data()),
                               asymm::Signature(chunk.signature()),
                               validating_key)) {
      LOG(kError) << "Failed to store " << Base32Substr(name) << ": signature verification failed";
      return kFailedSignatureCheck;
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kSignatureCheckError;
  }

  if (crypto::Hash<crypto::SHA512>(chunk.data() + chunk.signature()).string() !=
      RemoveTypeFromName(name).string()) {
    LOG(kError) << "Failed to validate " << Base32Substr(name) << ": chunk isn't hashable";
    return kNotHashable;
  }

  return kSuccess;
}

template <>
int ProcessDelete<ChunkType::kSignaturePacket>(
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
    LOG(kError) << "Failed to delete " << Base32Substr(name)
                << ": signature verification failed";
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
int ProcessModify<ChunkType::kSignaturePacket>(
    const ChunkId& name,
    const std::string& /*content*/,
    const asymm::PublicKey& /*public_key*/,
    int64_t * /*size_difference*/,
    std::string * /*new_content*/,
    std::shared_ptr<chunk_store::ChunkStore> /*chunk_store*/) {
  LOG(kError) << "Failed to modify " << Base32Substr(name) << ": no modify of SignedData allowed";
  return kInvalidModify;
}

template <>
int ProcessHas<ChunkType::kSignaturePacket>(const ChunkId& name,
                                            const std::string& /*version*/,
                                            const asymm::PublicKey& /*public_key*/,
                                            std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  if (!chunk_store->Has(name)) {
    LOG(kError) << "Failed to find " << Base32Substr(name);
    return kFailedToFindChunk;
  }

  return kSuccess;
}

}  // namespace detail

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe
