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

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/utils.h"

#include "maidsafe/private/chunk_store/chunk_store.h"

namespace maidsafe {

namespace priv {

namespace chunk_actions {

namespace detail {

template <>
bool IsCacheable<ChunkType::kAppendableByAll>() { return false; }

template <>
bool IsModifiable<ChunkType::kAppendableByAll>() { return true; }

template <>
bool DoesModifyReplace<ChunkType::kAppendableByAll>() { return false; }

template <>
bool IsPayable<ChunkType::kAppendableByAll>() { return false; }

template <>
bool IsValidChunk<ChunkType::kAppendableByAll>(
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
std::string GetVersion<ChunkType::kAppendableByAll>(
    const ChunkId& name,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  std::string hash;
  return (GetContentAndTigerHash(name, chunk_store, nullptr, &hash) == kSuccess ? hash : "");
}

template <>
int ProcessGet<ChunkType::kAppendableByAll>(
    const ChunkId& name,
    const std::string& /*version*/,
    const asymm::PublicKey& public_key,
    std::string* existing_content,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  existing_content->clear();
  std::string all_existing_content(chunk_store->Get(name));
  if (all_existing_content.empty()) {
    LOG(kError) << "Failed to get " << Base32Substr(name);
    return kFailedToFindChunk;
  }

  AppendableByAll existing_chunk;
  if (!ParseProtobuf<AppendableByAll>(all_existing_content, &existing_chunk)) {
    LOG(kError) << "Failed to get " << Base32Substr(name)
                << ": existing data doesn't parse as AppendableByAll";
    return kParseFailure;
  }

  bool valid(false);
  try {
    valid = asymm::CheckSignature(
                asymm::PlainText(existing_chunk.allow_others_to_append().data()),
                asymm::Signature(existing_chunk.allow_others_to_append().signature()),
                public_key);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kSignatureCheckError;
  }

  if (valid) {
    // Owner - return all data
    *existing_content = all_existing_content;
    // and the content in the chunk shall be cleaned up later on via base class
    existing_chunk.clear_appendices();
    std::string with_empty_appendices;
    if (!existing_chunk.SerializeToString(&with_empty_appendices)) {
      LOG(kError) << "Failed to serialise: " << Base32Substr(name);
      return kSerialisationError;
    }
    if (!chunk_store->Modify(name, with_empty_appendices)) {
      LOG(kError) << "Failed to modify chunk: " << Base32Substr(name);
      return kModifyFailure;
    }
  } else {
    // Not owner - return only first value
    if (!existing_chunk.identity_key().SerializeToString(existing_content)) {
      LOG(kError) << "Failed to serialise: " << Base32Substr(name);
      return kSerialisationError;
    }
  }

  return kSuccess;
}

template <>
int ProcessStore<ChunkType::kAppendableByAll>(
    const ChunkId& name,
    const std::string& content,
    const asymm::PublicKey& public_key,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  if (chunk_store->Has(name)) {
    LOG(kWarning) << "Failed to store " << Base32Substr(name) << ": chunk already exists";
    return kKeyNotUnique;
  }

  AppendableByAll chunk;
  if (!ParseProtobuf<AppendableByAll>(content, &chunk)) {
    LOG(kError) << "Failed to store " << Base32Substr(name)
                << ": data doesn't parse as AppendableByAll";
    return kInvalidSignedData;
  }

  bool valid(false);
  try {
    valid = asymm::CheckSignature(asymm::PlainText(chunk.allow_others_to_append().data()),
                                  asymm::Signature(chunk.allow_others_to_append().signature()),
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
int ProcessDelete<ChunkType::kAppendableByAll>(
    const ChunkId& name,
    const std::string& ownership_proof,
    const asymm::PublicKey& public_key,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  std::string existing_content = chunk_store->Get(name);
  if (existing_content.empty()) {
    LOG(kInfo) << Base32Substr(name) << " already deleted";
    return kSuccess;
  }

  AppendableByAll existing_chunk;
  if (!ParseProtobuf<AppendableByAll>(existing_content, &existing_chunk)) {
    LOG(kError) << "Failed to delete " << Base32Substr(name)
                << ": existing data doesn't parse";
    return kParseFailure;
  }

  bool valid(false);
  try {
    valid = asymm::CheckSignature(
                asymm::PlainText(existing_chunk.allow_others_to_append().data()),
                asymm::Signature(existing_chunk.allow_others_to_append().signature()),
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
int ProcessModify<ChunkType::kAppendableByAll>(
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

  AppendableByAll existing_chunk;
  if (!ParseProtobuf<AppendableByAll>(existing_content, &existing_chunk)) {
    LOG(kError) << "Failed to modify " << Base32Substr(name)
                << ": existing data doesn't parse as AppendableByAll";
    return kParseFailure;
  }

  bool is_owner(false);
  try {
    is_owner = asymm::CheckSignature(
                asymm::PlainText(existing_chunk.allow_others_to_append().data()),
                asymm::Signature(existing_chunk.allow_others_to_append().signature()),
                public_key);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return kSignatureCheckError;
  }

  if (is_owner) {
    ModifyAppendableByAll chunk;
    if (!ParseProtobuf<ModifyAppendableByAll>(content, &chunk)) {
      LOG(kError) << "Failed to modify " << Base32Substr(name)
                  << ": data doesn't parse as ModifyAppendableByAll";
      return kInvalidSignedData;
    }

    bool has_allow_others_to_append(chunk.has_allow_others_to_append());
    bool has_identity_key(chunk.has_identity_key());

    // One and only one new_data of identity_key and allow_others_to_append
    // shall be provided via content
    if ((!has_allow_others_to_append) && (!has_identity_key)) {
      LOG(kError) << "Failed to modify " << Base32Substr(name)
                  << ": no new_control_content provided";
      return kInvalidModify;
    }
    if ((has_allow_others_to_append) && (has_identity_key)) {
      LOG(kError) << "Failed to modify " << Base32Substr(name)
                  << ": too much new_control_content provided";
      return kInvalidModify;
    }

    if (has_allow_others_to_append) {
      bool valid(false);
      try {
        valid = asymm::CheckSignature(asymm::PlainText(chunk.allow_others_to_append().data()),
                                      asymm::Signature(chunk.allow_others_to_append().signature()),
                                      public_key);
      }
      catch(const std::exception& e) {
        LOG(kError) << e.what();
        return kSignatureCheckError;
      }

      if (!valid) {
        LOG(kError) << "Failed to modify " << Base32Substr(name)
                    << ": signature verification failed";
        return kFailedSignatureCheck;
      }

      if (chunk.allow_others_to_append().data() == existing_chunk.allow_others_to_append().data()) {
        // TODO(qi.ma) the following clear is commented out as it already
        // happened in "processget" (get is guaranteed to happen before modify)

        // Remove appendices only
//        existing_chunk.clear_appendices();
//        if (!existing_chunk.SerializeToString(new_content)) {
//          LOG(kError) << "Failed to serialise: " << Base32Substr(name);
//          return kSerialisationError;
//        }
      } else {
        // Replace field only, leave appendices untouched
        existing_chunk.mutable_allow_others_to_append()->CopyFrom(chunk.allow_others_to_append());
        if (!existing_chunk.SerializeToString(new_content)) {
          LOG(kError) << "Failed to serialise: " << Base32Substr(name);
          return kSerialisationError;
        }
      }
    } else {
      bool valid(false);
      try {
        valid = asymm::CheckSignature(asymm::PlainText(chunk.identity_key().data()),
                                      asymm::Signature(chunk.identity_key().signature()),
                                      public_key);
      }
      catch(const std::exception& e) {
        LOG(kError) << e.what();
        return kSignatureCheckError;
      }

      if (!valid) {
        LOG(kError) << "Failed to modify " << Base32Substr(name)
                    << ": signature verification failed";
        return kFailedSignatureCheck;
      }
      // Replace field only, leave appendices untouched
      existing_chunk.mutable_identity_key()->CopyFrom(chunk.identity_key());
      if (!existing_chunk.SerializeToString(new_content)) {
        LOG(kError) << "Failed to serialise: " << Base32Substr(name);
        return kSerialisationError;
      }
    }
  } else {
    char appendability(existing_chunk.allow_others_to_append().data().at(0));
    if (static_cast<ChunkType>(appendability) == ChunkType::kAppendableByAll) {
      SignedData appendix;
      if (!ParseProtobuf<SignedData>(content, &appendix)) {
        LOG(kError) << "Failed to modify " << Base32Substr(name)
                    << ": data doesn't parse as SignedData";
        return kInvalidSignedData;
      }

      bool valid(false);
      try {
        valid = asymm::CheckSignature(asymm::PlainText(appendix.data()),
                                      asymm::Signature(appendix.signature()),
                                      public_key);
      }
      catch(const std::exception& e) {
        LOG(kError) << e.what();
        return kSignatureCheckError;
      }

      if (!valid) {
        LOG(kError) << "Failed to modify " << Base32Substr(name)
                    << ": signature verification failed";
        return kFailedSignatureCheck;
      }

      existing_chunk.add_appendices()->CopyFrom(appendix);
      if (!existing_chunk.SerializeToString(new_content)) {
        LOG(kError) << "Failed to serialise: " << Base32Substr(name);
        return kSerialisationError;
      }
    } else {
      LOG(kInfo) << "Failed to modify " << Base32Substr(name) << ": appending disallowed by owner";
      return kAppendDisallowed;
    }
  }

  *size_difference = static_cast<int64_t>(existing_content.size()) - new_content->size();
  return kSuccess;
}

template <>
int ProcessHas<ChunkType::kAppendableByAll>(
    const ChunkId& name,
    const std::string& /*version*/,
    const asymm::PublicKey& /*public_key*/,
    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  if (!chunk_store->Has(name)) {
    LOG(kWarning) << "Failed to find " << Base32Substr(name);
    return kFailedToFindChunk;
  }

  return kSuccess;
}

}  // namespace detail

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe
