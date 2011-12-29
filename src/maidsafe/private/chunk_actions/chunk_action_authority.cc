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

std::string ApplyTypeToName(const std::string &name, unsigned char chunk_type) {
  if (name.size() != static_cast<size_t>(crypto::SHA512::DIGESTSIZE)) {
    DLOG(ERROR) << "Name " << Base32Substr(name) << " is " << name.size()
                << " chars. Must be " << crypto::SHA512::DIGESTSIZE << " chars";
    return "";
  }

  return chunk_type == chunk_actions::kDefaultType ? name :
                                      name + static_cast<char>(chunk_type);
}

std::string RemoveTypeFromName(const std::string &name) {
  return name.substr(0, crypto::SHA512::DIGESTSIZE);
}

unsigned char GetDataType(const std::string &name) {
  if (name.size() == static_cast<size_t>(crypto::SHA512::DIGESTSIZE))
    return chunk_actions::kDefaultType;

  if (name.size() == crypto::SHA512::DIGESTSIZE + 1) {
    switch (*name.rbegin()) {
      case chunk_actions::kAppendableByAll:
        return chunk_actions::kAppendableByAll;
      case chunk_actions::kModifiableByOwner:
        return chunk_actions::kModifiableByOwner;
      case chunk_actions::kSignaturePacket:
        return chunk_actions::kSignaturePacket;
      default:
        break;
    }
  }
  DLOG(WARNING) << "Unknown data type " << static_cast<int>(*name.rbegin());
  return chunk_actions::kUnknownType;
}

}  // namespace chunk_actions


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

  if (chunk_actions::GetDataType(name) == chunk_actions::kSignaturePacket) {
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
  return (chunk_actions::GetDataType(name) != chunk_actions::kUnknownType);
}

bool ChunkActionAuthority::Cacheable(const std::string &name) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::IsCacheable<chunk_actions::kDefaultType>();
    case chunk_actions::kAppendableByAll:
      return chunk_actions::IsCacheable<chunk_actions::kAppendableByAll>();
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::IsCacheable<chunk_actions::kModifiableByOwner>();
    case chunk_actions::kSignaturePacket:
      return chunk_actions::IsCacheable<chunk_actions::kSignaturePacket>();
    case chunk_actions::kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type "
                  << static_cast<int>(chunk_actions::GetDataType(name));
      return false;
  }
}

bool ChunkActionAuthority::ValidChunk(const std::string &name) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::IsValidChunk<chunk_actions::kDefaultType>(name,
                 chunk_store_);
    case chunk_actions::kAppendableByAll:
      return chunk_actions::IsValidChunk<chunk_actions::kAppendableByAll>(name,
                 chunk_store_);
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::IsValidChunk<chunk_actions::kModifiableByOwner>(
                 name, chunk_store_);
    case chunk_actions::kSignaturePacket:
      return chunk_actions::IsValidChunk<chunk_actions::kSignaturePacket>(name,
                 chunk_store_);
    case chunk_actions::kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type "
                  << static_cast<int>(chunk_actions::GetDataType(name));
      return false;
  }
}

std::string ChunkActionAuthority::Version(const std::string &name) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::GetVersion<chunk_actions::kDefaultType>(name,
                 chunk_store_);
    case chunk_actions::kAppendableByAll:
      return chunk_actions::GetVersion<chunk_actions::kAppendableByAll>(name,
                 chunk_store_);
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::GetVersion<chunk_actions::kModifiableByOwner>(name,
                 chunk_store_);
    case chunk_actions::kSignaturePacket:
      return chunk_actions::GetVersion<chunk_actions::kSignaturePacket>(name,
                 chunk_store_);
    case chunk_actions::kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type "
                  << static_cast<int>(chunk_actions::GetDataType(name));
      return "";
  }
}

int ChunkActionAuthority::ValidGet(const std::string &name,
                                   const std::string &version,
                                   const asymm::PublicKey &public_key,
                                   std::string *existing_content) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::ProcessGet<chunk_actions::kDefaultType>(name,
                 version, public_key, existing_content, chunk_store_);
    case chunk_actions::kAppendableByAll:
      return chunk_actions::ProcessGet<chunk_actions::kAppendableByAll>(name,
                 version, public_key, existing_content, chunk_store_);
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::ProcessGet<chunk_actions::kModifiableByOwner>(name,
                 version, public_key, existing_content, chunk_store_);
    case chunk_actions::kSignaturePacket:
      return chunk_actions::ProcessGet<chunk_actions::kSignaturePacket>(name,
                 version, public_key, existing_content, chunk_store_);
    case chunk_actions::kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type "
                  << static_cast<int>(chunk_actions::GetDataType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidStore(const std::string &name,
                                     const std::string &content,
                                     const asymm::PublicKey &public_key) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::ProcessStore<chunk_actions::kDefaultType>(name,
                 content, public_key, chunk_store_);
    case chunk_actions::kAppendableByAll:
      return chunk_actions::ProcessStore<chunk_actions::kAppendableByAll>(name,
                 content, public_key, chunk_store_);
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::ProcessStore<chunk_actions::kModifiableByOwner>(
                 name, content, public_key, chunk_store_);
    case chunk_actions::kSignaturePacket:
      return chunk_actions::ProcessStore<chunk_actions::kSignaturePacket>(name,
                 content, public_key, chunk_store_);
    case chunk_actions::kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type "
                  << static_cast<int>(chunk_actions::GetDataType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidDelete(
    const std::string &name,
    const std::string &version,
    const std::string &ownership_proof,
    const asymm::PublicKey &public_key) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::ProcessDelete<chunk_actions::kDefaultType>(name,
                 version, ownership_proof, public_key, chunk_store_);
    case chunk_actions::kAppendableByAll:
      return chunk_actions::ProcessDelete<chunk_actions::kAppendableByAll>(name,
                 version, ownership_proof, public_key, chunk_store_);
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::ProcessDelete<chunk_actions::kModifiableByOwner>(
                 name, version, ownership_proof, public_key, chunk_store_);
    case chunk_actions::kSignaturePacket:
      return chunk_actions::ProcessDelete<chunk_actions::kSignaturePacket>(name,
                 version, ownership_proof, public_key, chunk_store_);
    case chunk_actions::kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type "
                  << static_cast<int>(chunk_actions::GetDataType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidModify(const std::string &name,
                                      const std::string &content,
                                      const std::string &version,
                                      const asymm::PublicKey &public_key,
                                      std::string *new_content) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::ProcessModify<chunk_actions::kDefaultType>(name,
                 content, version, public_key, new_content, chunk_store_);
    case chunk_actions::kAppendableByAll:
      return chunk_actions::ProcessModify<chunk_actions::kAppendableByAll>(name,
                 content, version, public_key, new_content, chunk_store_);
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::ProcessModify<chunk_actions::kModifiableByOwner>(
                 name, content, version, public_key, new_content, chunk_store_);
    case chunk_actions::kSignaturePacket:
      return chunk_actions::ProcessModify<chunk_actions::kSignaturePacket>(name,
                 content, version, public_key, new_content, chunk_store_);
    case chunk_actions::kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type "
                  << static_cast<int>(chunk_actions::GetDataType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidHas(const std::string &name,
                                   const std::string &version,
                                   const asymm::PublicKey &public_key) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::ProcessHas<chunk_actions::kDefaultType>(name,
                 version, public_key, chunk_store_);
    case chunk_actions::kAppendableByAll:
      return chunk_actions::ProcessHas<chunk_actions::kAppendableByAll>(name,
                 version, public_key, chunk_store_);
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::ProcessHas<chunk_actions::kModifiableByOwner>(name,
                 version, public_key, chunk_store_);
    case chunk_actions::kSignaturePacket:
      return chunk_actions::ProcessHas<chunk_actions::kSignaturePacket>(name,
                 version, public_key, chunk_store_);
    case chunk_actions::kUnknownType:
    default:
      DLOG(ERROR) << "Unknown type "
                  << static_cast<int>(chunk_actions::GetDataType(name));
      return kInvalidChunkType;
  }
}

}  // namespace priv

}  // namespace maidsafe

