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

#include "maidsafe/common/chunk_action_authority.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/signature_packet_pb.h"
#include "maidsafe/private/chunk_actions/utils.h"
#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"


namespace maidsafe {

namespace priv {

namespace chunk_actions {

template <>
bool IsCacheable<kSignaturePacket>() { return false; }

template <>
bool IsValidChunk<kSignaturePacket>(const std::string &name,
                                    std::shared_ptr<ChunkStore> chunk_store) {
  std::string existing_data;
  existing_data = chunk_store->Get(name);
  if (existing_data.empty()) {
    DLOG(ERROR) << "Failed to get " << Base32Substr(name) << " for validation";
    return false;
  }

  SignaturePacket existing_chunk;
  if (!ParseProtobuf<SignaturePacket>(existing_data, &existing_chunk)) {
    DLOG(ERROR) << "Failed to validate " << Base32Substr(name)
                << ": existing data doesn't parse as a SignaturePacket";
    return false;
  }

  if (crypto::Hash<crypto::SHA512>(
        existing_chunk.public_key() + existing_chunk.public_key_signature()) !=
      name) {
    DLOG(ERROR) << "Failed to validate " << Base32Substr(name)
                << ": chunk isn't hashable";
    return false;
  }

  return true;
}

template <>
int ProcessGet<kSignaturePacket>(const std::string &name,
                                 const std::string &/*version*/,
                                 const asymm::PublicKey &/*public_key*/,
                                 std::string *existing_content,
                                 std::shared_ptr<ChunkStore> chunk_store) {
  *existing_content = chunk_store->Get(name);
  if (existing_content->empty()) {
    DLOG(WARNING) << "Failed to get " << Base32Substr(name);
    return kFailedToFindChunk;
  }

  return kSuccess;
}

template <>
int ProcessStore<kSignaturePacket>(const std::string &name,
                             const std::string &content,
                             const asymm::PublicKey &public_key,
                             std::shared_ptr<ChunkStore> chunk_store) {
  if (chunk_store->Has(name)) {
    DLOG(WARNING) << "Failed to store " << Base32Substr(name)
                  << ": chunk already exists";
    return kKeyNotUnique;
  }

  SignaturePacket chunk;
  if (!ParseProtobuf<SignaturePacket>(content, &chunk)) {
    DLOG(ERROR) << "Failed to store " << Base32Substr(name)
                << ": data doesn't parse as a SignaturePacket";
    return kInvalidSignedData;
  }

  if (!asymm::ValidateKey(public_key)) {
    DLOG(ERROR) << "Failed to store " << Base32Substr(name)
                << ": invalid public key";
    return kInvalidPublicKey;
  }

  if (asymm::CheckSignature(chunk.public_key(), chunk.public_key_signature(),
                            public_key) != kSuccess) {
    DLOG(ERROR) << "Failed to store " << Base32Substr(name)
                << ": signature verification failed";
    return kSignatureVerificationFailure;
  }

  if (crypto::Hash<crypto::SHA512>(
          chunk.public_key() + chunk.public_key_signature()) != name) {
    DLOG(ERROR) << "Failed to validate " << Base32Substr(name)
                << ": chunk isn't hashable";
    return kNotHashable;
  }

  return kSuccess;
}

template <>
int ProcessDelete<kSignaturePacket>(const std::string &name,
                                    const std::string &/*version*/,
                                    const asymm::PublicKey &public_key,
                                    std::shared_ptr<ChunkStore> chunk_store) {
  std::string existing_content = chunk_store->Get(name);
  if (existing_content.empty()) {
    DLOG(INFO) << Base32Substr(name) << " already deleted";
    return kSuccess;
  }

  SignaturePacket existing_chunk;
  if (!ParseProtobuf<SignaturePacket>(existing_content, &existing_chunk)) {
    DLOG(ERROR) << "Failed to delete " << Base32Substr(name)
                << ": existing data doesn't parse";
    return kGeneralError;
  }

  if (!asymm::ValidateKey(public_key)) {
    DLOG(ERROR) << "Failed to delete " << Base32Substr(name)
                << ": invalid public key";
    return kInvalidPublicKey;
  }

  if (asymm::CheckSignature(existing_chunk.public_key(),
                            existing_chunk.public_key_signature(),
                            public_key) != kSuccess) {
    DLOG(ERROR) << "Failed to delete " << Base32Substr(name)
                << ": signature verification failed";
    return kSignatureVerificationFailure;
  }

  // TODO(Fraser#5#): 2011-12-19 - Add verification that sender owns
  //                               corresponding private key (uncomment below)
//  DeletionToken deletion_token;
//  if (!ParseProtobuf<DeletionToken>(serialised_deletion_token,
//                                    &deletion_token)) {
//    DLOG(ERROR) << "Failed to delete " << Base32Substr(name)
//                << ": deletion_token doesn't parse - not owner";
//    return kNotOwner;
//  }
//  if (asymm::CheckSignature(deletion_token.data(), deletion_token.signature(),
//                            public_key) != kSuccess) {
//    DLOG(ERROR) << "Failed to delete " << Base32Substr(name)
//                << ": signature verification failed - not owner";
//    return kNotOwner;
//  }

  return kSuccess;
}

template <>
int ProcessModify<kSignaturePacket>(const std::string &name,
                                    const std::string &/*content*/,
                                    const std::string &/*version*/,
                                    const asymm::PublicKey &/*public_key*/,
                                    std::string * /*new_content*/,
                                    std::shared_ptr<ChunkStore> /*chunk_store*/) {
  DLOG(ERROR) << "Failed to modify " << Base32Substr(name)
              << ": no modify of SignaturePacket allowed";
  return kInvalidModify;
}

template <>
int ProcessHas<kSignaturePacket>(const std::string &name,
                                 const std::string &/*version*/,
                                 const asymm::PublicKey &/*public_key*/,
                                 std::shared_ptr<ChunkStore> chunk_store) {
  if (!chunk_store->Has(name)) {
    DLOG(WARNING) << "Failed to find " << Base32Substr(name);
    return kFailedToFindChunk;
  }

  return kSuccess;
}

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe
