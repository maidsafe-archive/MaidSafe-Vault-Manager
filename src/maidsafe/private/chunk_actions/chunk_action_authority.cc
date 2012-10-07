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
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"

#include "maidsafe/private/chunk_actions/chunk_type.h"
#include "maidsafe/private/chunk_actions/default_rules.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_rules.h"
#include "maidsafe/private/chunk_actions/modifiable_by_owner_rules.h"
#include "maidsafe/private/chunk_actions/signature_packet_rules.h"
#include "maidsafe/private/chunk_actions/utils.h"

#include "maidsafe/private/chunk_store/chunk_store.h"


namespace maidsafe {

namespace priv {

namespace chunk_actions {

ChunkActionAuthority::ChunkActionAuthority(std::shared_ptr<chunk_store::ChunkStore> chunk_store)
    : chunk_store_(chunk_store) {}

ChunkActionAuthority::~ChunkActionAuthority() {}

std::string ChunkActionAuthority::Get(const ChunkId& name,
                                      const ChunkVersion& version,
                                      const asymm::PublicKey& public_key) const {
  std::string existing_content;
  int result(ValidGet(name, version, public_key, &existing_content));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get " << Base32Substr(name) << ": " << result;
    existing_content.clear();
  }

  return existing_content;
}

bool ChunkActionAuthority::Get(const ChunkId& name,
                               const fs::path& sink_file_name,
                               const ChunkVersion& version,
                               const asymm::PublicKey& public_key) const {
  std::string existing_content;
  int result(ValidGet(name, version, public_key, &existing_content));
  if (result != kSuccess) {
    LOG(kError) << "Failed to get " << Base32Substr(name) << ": " << result;
    return false;
  }

  if (!WriteFile(sink_file_name, existing_content)) {
    LOG(kError) << "Failed to write chunk " << Base32Substr(name) << " to "
                << sink_file_name;
    return false;
  }

  return true;
}

bool ChunkActionAuthority::Store(const ChunkId& name,
                                 const std::string& content,
                                 const asymm::PublicKey& public_key) {
  int result(ValidStore(name, content, public_key));
  if (result != kSuccess) {
    LOG(kError) << "Invalid request to store " << Base32Substr(name) << ": " << result;
    return false;
  }

  if (!chunk_store_->Store(name, content)) {
    LOG(kError) << "Failed to store " << Base32Substr(name);
    return false;
  }

  return true;
}

bool ChunkActionAuthority::Store(const ChunkId& name,
                                 const fs::path& source_file_name,
                                 bool delete_source_file,
                                 const asymm::PublicKey& public_key) {
  std::string content;
  if (!ReadFile(source_file_name, &content)) {
    LOG(kError) << "Failed to read " << source_file_name;
    return false;
  }

  int result(ValidStore(name, content, public_key));
  if (result != kSuccess) {
    LOG(kError) << "Invalid request to store " << Base32Substr(name) << ": " << result;
    return false;
  }

  if (!chunk_store_->Store(name, content)) {
    LOG(kError) << "Failed to store " << Base32Substr(name);
    return false;
  }

  if (delete_source_file) {
    boost::system::error_code error_code;
#ifdef DEBUG
    bool removed(fs::remove(source_file_name, error_code));
    if (!removed) {
      LOG(kWarning) << "Failed to remove source file " << source_file_name
                    << (error_code ? (": " + error_code.message()) : "");
    }
#else
    fs::remove(source_file_name, error_code);
#endif
  }

  return true;
}

bool ChunkActionAuthority::Delete(const ChunkId& name,
                                  const std::string& ownership_proof,
                                  const asymm::PublicKey& public_key) {
  int result(ValidDelete(name, ownership_proof, public_key));
  if (result != kSuccess) {
    LOG(kError) << "Invalid request to delete " << Base32Substr(name) << ": " << result;
    return false;
  }

  if (!chunk_store_->Delete(name)) {
    LOG(kError) << "Failed to delete " << Base32Substr(name);
    return false;
  }

  return true;
}

bool ChunkActionAuthority::Modify(const ChunkId& name,
                                  const std::string& content,
                                  const asymm::PublicKey& public_key,
                                  int64_t* size_difference) {
  std::string new_content;
  int result(ValidModify(name, content, public_key, size_difference, &new_content));
  if (result != kSuccess) {
    LOG(kError) << "Invalid request to modify " << Base32Substr(name) << ": " << result;
    return false;
  }

  if (!chunk_store_->Modify(name, new_content)) {
    LOG(kError) << "Failed to modify " << Base32Substr(name);
    return false;
  }

  return true;
}

bool ChunkActionAuthority::Modify(const ChunkId& name,
                                  const fs::path& source_file_name,
                                  bool delete_source_file,
                                  const asymm::PublicKey& public_key,
                                  int64_t* size_difference) {
  std::string content;
  if (!ReadFile(source_file_name, &content)) {
    LOG(kError) << "Failed to read " << source_file_name;
    return false;
  }

  std::string new_content;
  int result(ValidModify(name, content, public_key, size_difference, &new_content));
  if (result != kSuccess) {
    LOG(kError) << "Invalid request to modify " << Base32Substr(name) << ": " << result;
    return false;
  }

  if (!chunk_store_->Modify(name, new_content)) {
    LOG(kError) << "Failed to modify " << Base32Substr(name);
    return false;
  }

  if (delete_source_file) {
    boost::system::error_code error_code;
#ifdef DEBUG
    bool removed(fs::remove(source_file_name, error_code));
    if (!removed) {
      LOG(kWarning) << "Failed to remove source file " << source_file_name
                    << (error_code ? (": " + error_code.message()) : "");
    }
#else
    fs::remove(source_file_name, error_code);
#endif
  }

  return true;
}

bool ChunkActionAuthority::Has(const ChunkId& name,
                               const ChunkVersion& version,
                               const asymm::PublicKey& public_key) const {
  int result(ValidHas(name, version, public_key));
  if (result != kSuccess) {
    LOG(kWarning) << "Invalid request or doesn't have " << Base32Substr(name)
                  << ": " << result;
    return false;
  }

  return true;
}

bool ChunkActionAuthority::ValidName(const ChunkId& name) const {
  return (GetChunkType(name) != ChunkType::kUnknown);
}

bool ChunkActionAuthority::Cacheable(const ChunkId& name) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::IsCacheable<ChunkType::kDefault>();
    case ChunkType::kAppendableByAll:
      return detail::IsCacheable<ChunkType::kAppendableByAll>();
    case ChunkType::kModifiableByOwner:
      return detail::IsCacheable<ChunkType::kModifiableByOwner>();
    case ChunkType::kSignaturePacket:
      return detail::IsCacheable<ChunkType::kSignaturePacket>();
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return false;
  }
}

bool ChunkActionAuthority::Modifiable(const ChunkId& name) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::IsModifiable<ChunkType::kDefault>();
    case ChunkType::kAppendableByAll:
      return detail::IsModifiable<ChunkType::kAppendableByAll>();
    case ChunkType::kModifiableByOwner:
      return detail::IsModifiable<ChunkType::kModifiableByOwner>();
    case ChunkType::kSignaturePacket:
      return detail::IsModifiable<ChunkType::kSignaturePacket>();
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return false;
  }
}

bool ChunkActionAuthority::ModifyReplaces(const ChunkId& name) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::DoesModifyReplace<ChunkType::kDefault>();
    case ChunkType::kAppendableByAll:
      return detail::DoesModifyReplace<ChunkType::kAppendableByAll>();
    case ChunkType::kModifiableByOwner:
      return detail::DoesModifyReplace<ChunkType::kModifiableByOwner>();
    case ChunkType::kSignaturePacket:
      return detail::DoesModifyReplace<ChunkType::kSignaturePacket>();
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return false;
  }
}

bool ChunkActionAuthority::Payable(const ChunkId& name) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::IsPayable<ChunkType::kDefault>();
    case ChunkType::kAppendableByAll:
      return detail::IsPayable<ChunkType::kAppendableByAll>();
    case ChunkType::kModifiableByOwner:
      return detail::IsPayable<ChunkType::kModifiableByOwner>();
    case ChunkType::kSignaturePacket:
      return detail::IsPayable<ChunkType::kSignaturePacket>();
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return false;
  }
}

bool ChunkActionAuthority::ValidChunk(const ChunkId& name) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::IsValidChunk<ChunkType::kDefault>(name, chunk_store_);
    case ChunkType::kAppendableByAll:
      return detail::IsValidChunk<ChunkType::kAppendableByAll>(name, chunk_store_);
    case ChunkType::kModifiableByOwner:
      return detail::IsValidChunk<ChunkType::kModifiableByOwner>(name, chunk_store_);
    case ChunkType::kSignaturePacket:
      return detail::IsValidChunk<ChunkType::kSignaturePacket>(name, chunk_store_);
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return false;
  }
}

ChunkVersion ChunkActionAuthority::Version(const ChunkId& name) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::GetVersion<ChunkType::kDefault>(name, chunk_store_);
    case ChunkType::kAppendableByAll:
      return detail::GetVersion<ChunkType::kAppendableByAll>(name, chunk_store_);
    case ChunkType::kModifiableByOwner:
      return detail::GetVersion<ChunkType::kModifiableByOwner>(name, chunk_store_);
    case ChunkType::kSignaturePacket:
      return detail::GetVersion<ChunkType::kSignaturePacket>(name, chunk_store_);
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return ChunkVersion();
  }
}

int ChunkActionAuthority::ValidGet(const ChunkId& name,
                                   const ChunkVersion& version,
                                   const asymm::PublicKey& public_key,
                                   std::string* existing_content) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::ProcessGet<ChunkType::kDefault>(name, version, public_key, existing_content,
                                                     chunk_store_);
    case ChunkType::kAppendableByAll:
      return detail::ProcessGet<ChunkType::kAppendableByAll>(name, version, public_key,
                                                             existing_content, chunk_store_);
    case ChunkType::kModifiableByOwner:
      return detail::ProcessGet<ChunkType::kModifiableByOwner>(name, version, public_key,
                                                               existing_content, chunk_store_);
    case ChunkType::kSignaturePacket:
      return detail::ProcessGet<ChunkType::kSignaturePacket>(name, version, public_key,
                                                             existing_content, chunk_store_);
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidStore(const ChunkId& name,
                                     const std::string& content,
                                     const asymm::PublicKey& public_key) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::ProcessStore<ChunkType::kDefault>(name, content, public_key, chunk_store_);
    case ChunkType::kAppendableByAll:
      return detail::ProcessStore<ChunkType::kAppendableByAll>(name, content, public_key,
                                                               chunk_store_);
    case ChunkType::kModifiableByOwner:
      return detail::ProcessStore<ChunkType::kModifiableByOwner>(name, content, public_key,
                                                                 chunk_store_);
    case ChunkType::kSignaturePacket:
      return detail::ProcessStore<ChunkType::kSignaturePacket>(name, content, public_key,
                                                               chunk_store_);
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidDelete(const ChunkId& name,
                                      const std::string& ownership_proof,
                                      const asymm::PublicKey& public_key) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::ProcessDelete<ChunkType::kDefault>(name, ownership_proof, public_key,
                                                        chunk_store_);
    case ChunkType::kAppendableByAll:
      return detail::ProcessDelete<ChunkType::kAppendableByAll>(name, ownership_proof, public_key,
                                                        chunk_store_);
    case ChunkType::kModifiableByOwner:
      return detail::ProcessDelete<ChunkType::kModifiableByOwner>(name, ownership_proof, public_key,
                                                          chunk_store_);
    case ChunkType::kSignaturePacket:
      return detail::ProcessDelete<ChunkType::kSignaturePacket>(name, ownership_proof, public_key,
                                                        chunk_store_);
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidModify(const ChunkId& name,
                                      const std::string& content,
                                      const asymm::PublicKey& public_key,
                                      int64_t* size_difference,
                                      std::string* new_content) const {
  if (!size_difference) {
    LOG(kError) << "nullptr parameter passed.";
    return kNullParameter;
  }
  *size_difference = 0;

  std::string temp_new_content;
  if (!new_content)
    new_content = &temp_new_content;

  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::ProcessModify<ChunkType::kDefault>(name, content, public_key, size_difference,
                                                        new_content, chunk_store_);
    case ChunkType::kAppendableByAll:
      return detail::ProcessModify<ChunkType::kAppendableByAll>(name, content, public_key,
                                                                size_difference, new_content,
                                                                chunk_store_);
    case ChunkType::kModifiableByOwner:
      return detail::ProcessModify<ChunkType::kModifiableByOwner>(name, content, public_key,
                                                                  size_difference, new_content,
                                                                  chunk_store_);
    case ChunkType::kSignaturePacket:
      return detail::ProcessModify<ChunkType::kSignaturePacket>(name, content, public_key,
                                                                size_difference, new_content,
                                                                chunk_store_);
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return kInvalidChunkType;
  }
}

int ChunkActionAuthority::ValidHas(const ChunkId& name,
                                   const ChunkVersion& version,
                                   const asymm::PublicKey& public_key) const {
  switch (GetChunkType(name)) {
    case ChunkType::kDefault:
      return detail::ProcessHas<ChunkType::kDefault>(name, version, public_key, chunk_store_);
    case ChunkType::kAppendableByAll:
      return detail::ProcessHas<ChunkType::kAppendableByAll>(name, version, public_key,
                                                             chunk_store_);
    case ChunkType::kModifiableByOwner:
      return detail::ProcessHas<ChunkType::kModifiableByOwner>(name, version, public_key,
                                                               chunk_store_);
    case ChunkType::kSignaturePacket:
      return detail::ProcessHas<ChunkType::kSignaturePacket>(name, version, public_key,
                                                             chunk_store_);
    case ChunkType::kUnknown:
    default: LOG(kError) << "Unknown type " << static_cast<int>(GetChunkType(name));
      return kInvalidChunkType;
  }
}

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

