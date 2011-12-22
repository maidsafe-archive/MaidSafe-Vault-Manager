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

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_actions/default_rules.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_rules.h"
#include "maidsafe/private/chunk_actions/modifiable_by_owner_rules.h"
#include "maidsafe/private/chunk_actions/utils.h"


namespace maidsafe {

namespace priv {

namespace chunk_actions {

bool ChunkActionAuthority::Delete(const std::string &name,
                                  const std::string &version,
                                  const std::string &ownership_proof,
                                  const asymm::PublicKey &public_key) {
  int result(ValidDelete(name, version, ownership_proof, public_key));
  if (result != kSuccess) {
    DLOG(ERROR) << "Invalid request to delete " << Base32Substr(name) << ": "
                << result;
    return false;
  }

  if (GetDataType(name) == kSignaturePacket) {
    if (!chunk_store_->Modify(name, 0)) {
      DLOG(ERROR) << "Failed to invalidate " << Base32Substr(name);
      return false;
    }
  } else {
    if (!chunk_store_->Delete(name)) {
      DLOG(ERROR) << "Failed to delete " << Base32Substr(name);
      return false;
    }
  }

  return true;
}

bool ChunkActionAuthority::ValidName(const std::string &name) const {
  return (GetDataType(name) != kUnknownType);
}

bool ChunkActionAuthority::Cacheable(const std::string &name) const {
  switch (GetDataType(name)) {
    case kDefaultType:
      return IsCacheable<kDefaultType>();
    case kAppendableByAll:
      return IsCacheable<kAppendableByAll>();
    case kModifiableByOwner:
      return IsCacheable<kModifiableByOwner>();
    case kSignaturePacket:
      return IsCacheable<kSignaturePacket>();
    case kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type " << static_cast<int>(GetDataType(name));
      return false;
  }
}

bool ChunkActionAuthority::ValidChunk(const std::string &name) const {
  switch (GetDataType(name)) {
    case kDefaultType:
      return IsValidChunk<kDefaultType>(name, chunk_store_);
    case kAppendableByAll:
      return IsValidChunk<kAppendableByAll>(name, chunk_store_);
    case kModifiableByOwner:
      return IsValidChunk<kModifiableByOwner>(name, chunk_store_);
    case kSignaturePacket:
      return IsValidChunk<kSignaturePacket>(name, chunk_store_);
    case kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type " << static_cast<int>(GetDataType(name));
      return false;
  }
}

std::string ChunkActionAuthority::Version(const std::string &name) const {
  switch (GetDataType(name)) {
    case kDefaultType:
      return GetVersion<kDefaultType>(name, chunk_store_);
    case kAppendableByAll:
      return GetVersion<kAppendableByAll>(name, chunk_store_);
    case kModifiableByOwner:
      return GetVersion<kModifiableByOwner>(name, chunk_store_);
    case kSignaturePacket:
      return GetVersion<kSignaturePacket>(name, chunk_store_);
    case kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type " << static_cast<int>(GetDataType(name));
      return "";
  }
}

std::string ChunkActionAuthority::ApplyTypeToName(
    const std::string &name,
    unsigned char chunk_type) const {
  if (name.size() != crypto::SHA512::DIGESTSIZE) {
    DLOG(ERROR) << "Name " << Base32Substr(name) << " is " << name.size()
                << " chars. Must be " << crypto::SHA512::DIGESTSIZE << " chars";
    return "";
  }

  return chunk_type == kDefaultType ? name :
                                      name + static_cast<char>(chunk_type);
}

unsigned char ChunkActionAuthority::GetDataType(const std::string &name) const {
  if (name.size() == crypto::SHA512::DIGESTSIZE)
    return kDefaultType;

  if (name.size() == crypto::SHA512::DIGESTSIZE + 1) {
    switch (*name.rbegin()) {
      case kAppendableByAll:
        return kAppendableByAll;
      case kModifiableByOwner:
        return kModifiableByOwner;
      case kSignaturePacket:
        return kSignaturePacket;
      default:
        break;
    }
  }
  DLOG(WARNING) << "Unknown data type " << static_cast<int>(*name.rbegin());
  return kUnknownType;
}

int ChunkActionAuthority::ValidGet(const std::string &name,
                                   const std::string &version,
                                   const asymm::PublicKey &public_key,
                                   std::string *existing_content) const {
  switch (GetDataType(name)) {
    case kDefaultType:
      return ProcessGet<kDefaultType>(name, version, public_key,
                                      existing_content, chunk_store_);
    case kAppendableByAll:
      return ProcessGet<kAppendableByAll>(name, version, public_key,
                                          existing_content, chunk_store_);
    case kModifiableByOwner:
      return ProcessGet<kModifiableByOwner>(name, version, public_key,
                                            existing_content, chunk_store_);
    case kSignaturePacket:
      return ProcessGet<kSignaturePacket>(name, version, public_key,
                                          existing_content, chunk_store_);
    case kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type " << static_cast<int>(GetDataType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidStore(const std::string &name,
                                     const std::string &content,
                                     const asymm::PublicKey &public_key) const {
  switch (GetDataType(name)) {
    case kDefaultType:
      return ProcessStore<kDefaultType>(name, content, public_key,
                                        chunk_store_);
    case kAppendableByAll:
      return ProcessStore<kAppendableByAll>(name, content, public_key,
                                            chunk_store_);
    case kModifiableByOwner:
      return ProcessStore<kModifiableByOwner>(name, content, public_key,
                                              chunk_store_);
    case kSignaturePacket:
      return ProcessStore<kSignaturePacket>(name, content, public_key,
                                            chunk_store_);
    case kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type " << static_cast<int>(GetDataType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidDelete(
    const std::string &name,
    const std::string &version,
    const std::string &ownership_proof,
    const asymm::PublicKey &public_key) const {
  switch (GetDataType(name)) {
    case kDefaultType:
      return ProcessDelete<kDefaultType>(name, version, ownership_proof,
                                         public_key, chunk_store_);
    case kAppendableByAll:
      return ProcessDelete<kAppendableByAll>(name, version, ownership_proof,
                                             public_key, chunk_store_);
    case kModifiableByOwner:
      return ProcessDelete<kModifiableByOwner>(name, version, ownership_proof,
                                               public_key, chunk_store_);
    case kSignaturePacket:
      return ProcessDelete<kSignaturePacket>(name, version, ownership_proof,
                                             public_key, chunk_store_);
    case kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type " << static_cast<int>(GetDataType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidModify(const std::string &name,
                                      const std::string &content,
                                      const std::string &version,
                                      const asymm::PublicKey &public_key,
                                      std::string *new_content) const {
  switch (GetDataType(name)) {
    case kDefaultType:
      return ProcessModify<kDefaultType>(name, content, version, public_key,
                                         new_content, chunk_store_);
    case kAppendableByAll:
      return ProcessModify<kAppendableByAll>(name, content, version, public_key,
                                             new_content, chunk_store_);
    case kModifiableByOwner:
      return ProcessModify<kModifiableByOwner>(name, content, version,
                                               public_key, new_content,
                                               chunk_store_);
    case kSignaturePacket:
      return ProcessModify<kSignaturePacket>(name, content, version, public_key,
                                             new_content, chunk_store_);
    case kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type " << static_cast<int>(GetDataType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidHas(const std::string &name,
                                   const std::string &version,
                                   const asymm::PublicKey &public_key) const {
  switch (GetDataType(name)) {
    case kDefaultType:
      return ProcessHas<kDefaultType>(name, version, public_key, chunk_store_);
    case kAppendableByAll:
      return ProcessHas<kAppendableByAll>(name, version, public_key,
                                          chunk_store_);
    case kModifiableByOwner:
      return ProcessHas<kModifiableByOwner>(name, version, public_key,
                                            chunk_store_);
    case kSignaturePacket:
      return ProcessHas<kSignaturePacket>(name, version, public_key,
                                          chunk_store_);
    case kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type " << static_cast<int>(GetDataType(name));
      return kInvalidChunkType;
  }
}

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

