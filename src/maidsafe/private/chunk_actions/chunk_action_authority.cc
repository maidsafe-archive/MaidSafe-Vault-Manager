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

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"

#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_actions/default_rules.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_rules.h"
#include "maidsafe/private/chunk_actions/modifiable_by_owner_rules.h"
#include "maidsafe/private/chunk_actions/signature_packet_rules.h"
#include "maidsafe/private/chunk_actions/utils.h"

#include "maidsafe/private/chunk_store/chunk_store.h"


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

  if (name.size() != crypto::SHA512::DIGESTSIZE + 1) {
    DLOG(WARNING) << "Unknown data type (invalid name size of " << name.size()
                  << ")";
    return chunk_actions::kUnknownType;
  }

  switch (*name.rbegin()) {
    case chunk_actions::kAppendableByAll:
      return chunk_actions::kAppendableByAll;
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::kModifiableByOwner;
    case chunk_actions::kSignaturePacket:
      return chunk_actions::kSignaturePacket;
    default:
      DLOG(WARNING) << "Unknown data type "
                    << static_cast<int>(*name.rbegin());
      return chunk_actions::kUnknownType;
  }
}

ChunkActionAuthority::ChunkActionAuthority(
    std::shared_ptr<chunk_store::ChunkStore> chunk_store)
    : chunk_store_(chunk_store) {}

ChunkActionAuthority::~ChunkActionAuthority() {}

std::string ChunkActionAuthority::Get(
      const std::string &name,
      const std::string &version,
      const asymm::PublicKey &public_key) const {
  std::string existing_content;
  int result(ValidGet(name, version, public_key, &existing_content));
  if (result != kSuccess) {
    DLOG(WARNING) << "Failed to get " << Base32Substr(name) << ": " << result;
    existing_content.clear();
  }

  return existing_content;
}

bool ChunkActionAuthority::Get(const std::string &name,
                               const fs::path &sink_file_name,
                               const std::string &version,
                               const asymm::PublicKey &public_key) const {
  std::string existing_content;
  int result(ValidGet(name, version, public_key, &existing_content));
  if (result != kSuccess) {
    DLOG(WARNING) << "Failed to get " << Base32Substr(name) << ": " << result;
    return false;
  }

  if (!WriteFile(sink_file_name, existing_content)) {
    DLOG(ERROR) << "Failed to write chunk " << Base32Substr(name) << " to "
                << sink_file_name;
    return false;
  }

  return true;
}

bool ChunkActionAuthority::Store(const std::string &name,
                                 const std::string &content,
                                 const asymm::PublicKey &public_key) {
  int result(ValidStore(name, content, public_key));
  if (result != kSuccess) {
    DLOG(ERROR) << "Invalid request to store " << Base32Substr(name) << ": "
                << result;
    return false;
  }

  if (!chunk_store_->Store(name, content)) {
    DLOG(ERROR) << "Failed to store " << Base32Substr(name);
    return false;
  }

  return true;
}

bool ChunkActionAuthority::Store(const std::string &name,
                                 const fs::path &source_file_name,
                                 bool delete_source_file,
                                 const asymm::PublicKey &public_key) {
  std::string content;
  if (!ReadFile(source_file_name, &content)) {
    DLOG(ERROR) << "Failed to read " << source_file_name;
    return false;
  }

  int result(ValidStore(name, content, public_key));
  if (result != kSuccess) {
    DLOG(ERROR) << "Invalid request to store " << Base32Substr(name) << ": "
                << result;
    return false;
  }

  if (!chunk_store_->Store(name, content)) {
    DLOG(ERROR) << "Failed to store " << Base32Substr(name);
    return false;
  }

  if (delete_source_file) {
    boost::system::error_code error_code;
#ifdef DEBUG
    bool removed(fs::remove(source_file_name, error_code));
    if (!removed) {
      DLOG(WARNING) << "Failed to remove source file " << source_file_name
                    << (error_code ? (": " + error_code.message()) : "");
    }
#else
    fs::remove(source_file_name, error_code);
#endif
  }

  return true;
}

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

  if (!chunk_store_->Delete(name)) {
    DLOG(ERROR) << "Failed to delete " << Base32Substr(name);
    return false;
  }

  return true;
}

bool ChunkActionAuthority::Modify(const std::string &name,
                                  const std::string &content,
                                  const asymm::PublicKey &public_key,
                                  int64_t *size_difference) {
  std::string new_content;
  int result(ValidModify(name, content, public_key, size_difference,
                         &new_content));
  if (result != kSuccess) {
    DLOG(ERROR) << "Invalid request to modify " << Base32Substr(name) << ": "
                << result;
    return false;
  }

  if (!chunk_store_->Modify(name, new_content)) {
    DLOG(ERROR) << "Failed to modify " << Base32Substr(name);
    return false;
  }

  return true;
}

bool ChunkActionAuthority::Modify(const std::string &name,
                                  const fs::path &source_file_name,
                                  bool delete_source_file,
                                  const asymm::PublicKey &public_key,
                                  int64_t *size_difference) {
  std::string content;
  if (!ReadFile(source_file_name, &content)) {
    DLOG(ERROR) << "Failed to read " << source_file_name;
    return false;
  }

  std::string new_content;
  int result(ValidModify(name, content, public_key, size_difference,
                         &new_content));
  if (result != kSuccess) {
    DLOG(ERROR) << "Invalid request to modify " << Base32Substr(name) << ": "
                << result;
    return false;
  }

  if (!chunk_store_->Modify(name, new_content)) {
    DLOG(ERROR) << "Failed to modify " << Base32Substr(name);
    return false;
  }

  if (delete_source_file) {
    boost::system::error_code error_code;
#ifdef DEBUG
    bool removed(fs::remove(source_file_name, error_code));
    if (!removed) {
      DLOG(WARNING) << "Failed to remove source file " << source_file_name
                    << (error_code ? (": " + error_code.message()) : "");
    }
#else
    fs::remove(source_file_name, error_code);
#endif
  }

  return true;
}

bool ChunkActionAuthority::Has(const std::string &name,
                               const std::string &version,
                               const asymm::PublicKey &public_key) const {
  int result(ValidHas(name, version, public_key));
  if (result != kSuccess) {
    DLOG(WARNING) << "Invalid request or doesn't have " << Base32Substr(name)
                  << ": " << result;
    return false;
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

bool ChunkActionAuthority::Modifiable(const std::string &name) const {
  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::IsModifiable<chunk_actions::kDefaultType>();
    case chunk_actions::kAppendableByAll:
      return chunk_actions::IsModifiable<chunk_actions::kAppendableByAll>();
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::IsModifiable<chunk_actions::kModifiableByOwner>();
    case chunk_actions::kSignaturePacket:
      return chunk_actions::IsModifiable<chunk_actions::kSignaturePacket>();
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
                                      const asymm::PublicKey &public_key,
                                      int64_t *size_difference,
                                      std::string *new_content) const {
  if (!size_difference) {
    DLOG(ERROR) << "nullptr parameter passed.";
    return kNullParameter;
  }
  *size_difference = 0;

  std::string temp_new_content;
  if (!new_content)
    new_content = &temp_new_content;

  switch (chunk_actions::GetDataType(name)) {
    case chunk_actions::kDefaultType:
      return chunk_actions::ProcessModify<chunk_actions::kDefaultType>(name,
                 content, public_key, size_difference, new_content,
                 chunk_store_);
    case chunk_actions::kAppendableByAll:
      return chunk_actions::ProcessModify<chunk_actions::kAppendableByAll>(name,
                 content, public_key, size_difference, new_content,
                 chunk_store_);
    case chunk_actions::kModifiableByOwner:
      return chunk_actions::ProcessModify<chunk_actions::kModifiableByOwner>(
                 name, content, public_key, size_difference, new_content,
                 chunk_store_);
    case chunk_actions::kSignaturePacket:
      return chunk_actions::ProcessModify<chunk_actions::kSignaturePacket>(name,
                 content, public_key, size_difference, new_content,
                 chunk_store_);
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

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

