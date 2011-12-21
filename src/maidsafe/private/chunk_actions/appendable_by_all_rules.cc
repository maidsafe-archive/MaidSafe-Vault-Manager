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

#include "maidsafe/private/chunk_actions/appendable_by_all_rules.h"

#include "maidsafe/common/chunk_action_authority.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/utils.h"


namespace maidsafe {

namespace priv {

namespace chunk_actions {

template <>
bool IsCacheable<kAppendableByAll>() { return false; }

template <>
bool IsValidChunk<kAppendableByAll>(const std::string &name,
                                    std::shared_ptr<ChunkStore> chunk_store) {
  // TODO(Fraser#5#): 2011-12-17 - Check this is all that's needed here
  std::string existing_data;
  existing_data = chunk_store->Get(name);
  if (existing_data.empty()) {
    DLOG(ERROR) << "Failed to get " << Base32Substr(name) << " for validation";
    return false;
  }
  return true;
}

template <>
std::string GetVersion<kAppendableByAll>(
    const std::string &name,
    std::shared_ptr<ChunkStore> chunk_store) {
  return GetTigerHash(name, chunk_store);
}

template <>
int ProcessGet<kAppendableByAll>(const std::string &name,
                                 const std::string &/*version*/,
                                 const asymm::PublicKey &public_key,
                                 std::string *existing_content,
                                 std::shared_ptr<ChunkStore> chunk_store) {
  existing_content->clear();
  std::string all_existing_content = chunk_store->Get(name);
  if (all_existing_content.empty()) {
    DLOG(WARNING) << "Failed to get " << Base32Substr(name);
    return kFailedToFindChunk;
  }

  AppendableByAll existing_chunk;
  if (!ParseProtobuf<AppendableByAll>(all_existing_content, &existing_chunk)) {
    DLOG(ERROR) << "Failed to get " << Base32Substr(name)
                << ": existing data doesn't parse as AppendableByAll";
    return kGeneralError;
  }

  if (!asymm::ValidateKey(public_key)) {
    DLOG(ERROR) << "Failed to get " << Base32Substr(name)
                << ": invalid public key";
    return kInvalidPublicKey;
  }

  if (asymm::CheckSignature(existing_chunk.control().data(),
                            existing_chunk.control().signature(),
                            public_key) == kSuccess) {
    // Owner - return all data
    *existing_content = all_existing_content;
  } else {
    // Not owner - return only first value
    existing_chunk.clear_appendices();
    BOOST_VERIFY(existing_chunk.SerializeToString(existing_content));
  }

  return kSuccess;
}

template <>
int ProcessStore<kAppendableByAll>(const std::string &name,
                                   const std::string &content,
                                   const asymm::PublicKey &public_key,
                                   std::shared_ptr<ChunkStore> chunk_store) {
  if (chunk_store->Has(name)) {
    DLOG(WARNING) << "Failed to store " << Base32Substr(name)
                  << ": chunk already exists";
    return kKeyNotUnique;
  }

  AppendableByAll chunk;
  if (!ParseProtobuf<AppendableByAll>(content, &chunk)) {
    DLOG(ERROR) << "Failed to store " << Base32Substr(name)
                << ": data doesn't parse as AppendableByAll";
    return kInvalidSignedData;
  }

  if (!asymm::ValidateKey(public_key)) {
    DLOG(ERROR) << "Failed to store " << Base32Substr(name)
                << ": invalid public key";
    return kInvalidPublicKey;
  }

  if (asymm::CheckSignature(chunk.control().data(), chunk.control().signature(),
                            public_key) != kSuccess) {
    DLOG(ERROR) << "Failed to store " << Base32Substr(name)
                << ": signature verification failed";
    return kSignatureVerificationFailure;
  }

  return kSuccess;
}

template <>
int ProcessDelete<kAppendableByAll>(const std::string &name,
                                    const std::string &/*version*/,
                                    const asymm::PublicKey &public_key,
                                    std::shared_ptr<ChunkStore> chunk_store) {
  std::string existing_content = chunk_store->Get(name);
  if (existing_content.empty()) {
    DLOG(INFO) << Base32Substr(name) << " already deleted";
    return kSuccess;
  }

  AppendableByAll existing_chunk;
  if (!ParseProtobuf<AppendableByAll>(existing_content, &existing_chunk)) {
    DLOG(ERROR) << "Failed to delete " << Base32Substr(name)
                << ": existing data doesn't parse";
    return kGeneralError;
  }

  if (!asymm::ValidateKey(public_key)) {
    DLOG(ERROR) << "Failed to delete " << Base32Substr(name)
                << ": invalid public key";
    return kInvalidPublicKey;
  }

  if (asymm::CheckSignature(existing_chunk.control().data(),
                            existing_chunk.control().signature(),
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
int ProcessModify<kAppendableByAll>(const std::string &name,
                                    const std::string &content,
                                    const std::string &/*version*/,
                                    const asymm::PublicKey &public_key,
                                    std::string *new_content,
                                    std::shared_ptr<ChunkStore> chunk_store) {
  new_content->clear();
  std::string existing_content = chunk_store->Get(name);
  if (existing_content.empty()) {
    DLOG(ERROR) << Base32Substr(name) << " doesn't exist";
    return kFailedToFindChunk;
  }

  AppendableByAll existing_chunk;
  if (!ParseProtobuf<AppendableByAll>(existing_content, &existing_chunk)) {
    DLOG(ERROR) << "Failed to modify " << Base32Substr(name)
                << ": existing data doesn't parse as AppendableByAll";
    return kGeneralError;
  }

  if (!asymm::ValidateKey(public_key)) {
    DLOG(ERROR) << "Failed to modify " << Base32Substr(name)
                << ": invalid public key";
    return kInvalidPublicKey;
  }

  bool is_owner(asymm::CheckSignature(existing_chunk.control().data(),
                                      existing_chunk.control().signature(),
                                      public_key) == kSuccess);

  if (is_owner) {
    AppendableByAll chunk;
    if (!ParseProtobuf<AppendableByAll>(content, &chunk)) {
      DLOG(ERROR) << "Failed to modify " << Base32Substr(name)
                  << ": data doesn't parse as AppendableByAll";
      return kInvalidSignedData;
    }

    if (asymm::CheckSignature(chunk.control().data(),
                              chunk.control().signature(),
                              public_key) != kSuccess) {
      DLOG(ERROR) << "Failed to modify " << Base32Substr(name)
                  << ": signature verification failed";
      return kSignatureVerificationFailure;
    }

    if (chunk.control().data() == existing_chunk.control().data()) {
      // Remove appendices only
      existing_chunk.clear_appendices();
      BOOST_VERIFY(existing_chunk.SerializeToString(new_content));
    } else {
      // Replace control chunk only, leave appendices untouched
      existing_chunk.mutable_control()->CopyFrom(chunk.control());
      BOOST_VERIFY(existing_chunk.SerializeToString(new_content));
    }
  } else {
    AppendableByAll::ControlInfo control_info;
    if (!ParseProtobuf<AppendableByAll::ControlInfo>(
            existing_chunk.control().data(), &control_info)) {
      DLOG(ERROR) << "Failed to modify " << Base32Substr(name)
                  << ": control_data doesn't parse";
      return kGeneralError;
    }

    if (control_info.allow_others_to_append()) {
      Chunk appendix;
      if (!ParseProtobuf<Chunk>(content, &appendix)) {
        DLOG(ERROR) << "Failed to modify " << Base32Substr(name)
                    << ": data doesn't parse as Chunk";
        return kInvalidSignedData;
      }

      if (asymm::CheckSignature(appendix.data(),
                                appendix.signature(),
                                public_key) != kSuccess) {
        DLOG(ERROR) << "Failed to modify " << Base32Substr(name)
                    << ": signature verification failed";
        return kSignatureVerificationFailure;
      }

      existing_chunk.add_appendices()->CopyFrom(appendix);
      BOOST_VERIFY(existing_chunk.SerializeToString(new_content));
    } else {
      DLOG(INFO) << "Failed to modify " << Base32Substr(name)
                 << ": appending disallowed by owner";
      return kAppendDisallowed;
    }
  }

  return kSuccess;
}

template <>
int ProcessHas<kAppendableByAll>(const std::string &name,
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
