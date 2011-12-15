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

#include "maidsafe/private/chunk_action_authority.h"

#include "maidsafe/common/chunk_store.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"
#include "maidsafe/private/detail/hashable_signed_rules.h"
#include "maidsafe/private/detail/mcid_rules.h"
#include "maidsafe/private/detail/mmid_rules.h"
#include "maidsafe/private/detail/msid_rules.h"


namespace maidsafe {

namespace priv {

int ChunkActionAuthority::ValidOperation(const int &op_type,
                            const std::string &name,
                            const std::string &content,
                            const asymm::PublicKey &public_key,
                            std::shared_ptr<ChunkStore> chunk_store,
                            std::string *new_content) const {
  switch(GetDataType(name)) {
    case kHashableSignedData:
      return detail::ProcessData<kHashableSignedData>(op_type, name, content,
                                                      public_key, chunk_store,
                                                      new_content);
    case kMcidData:
      return detail::ProcessData<kMcidData>(op_type, name, content, public_key,
                                            chunk_store, new_content);
    case kMmidData:
      return detail::ProcessData<kMmidData>(op_type, name, content, public_key,
                                            chunk_store, new_content);
    case kMsidData:
      return detail::ProcessData<kMsidData>(op_type, name, content, public_key,
                                            chunk_store, new_content);
    case kUnknownData:
    default:
      DLOG(ERROR) << "Unknown data type " << static_cast<int>(name.front());
      return kUnknownData;
  }
}

int ChunkActionAuthority::ValidOperation(const int &op_type,
                            const std::string &name,
                            const fs::path &path,
                            const asymm::PublicKey &public_key,
                            std::shared_ptr<ChunkStore> chunk_store,
                            std::string *new_content) const {
  switch(GetDataType(name)) {
    case kHashableSignedData:
      return detail::ProcessData<kHashableSignedData>(op_type, name, path,
                                                      public_key, chunk_store,
                                                      new_content);
    case kMcidData:
      return detail::ProcessData<kMcidData>(op_type, name, path, public_key,
                                            chunk_store, new_content);
    case kMmidData:
      return detail::ProcessData<kMmidData>(op_type, name, path, public_key,
                                            chunk_store, new_content);
    case kMsidData:
      return detail::ProcessData<kMsidData>(op_type, name, path, public_key,
                                            chunk_store, new_content);
    case kUnknownData:
    default:
      DLOG(ERROR) << "Unknown data type " << static_cast<int>(name.front());
      return kUnknownData;
  }
}

bool ChunkActionAuthority::ValidName(const std::string &name) const {}

bool ChunkActionAuthority::Cacheable(const std::string &name) const {}

bool ChunkActionAuthority::ValidChunk(const std::string &name,
                                      const std::string &content) const {}

bool ChunkActionAuthority::ValidChunk(const std::string &name,
                                      const fs::path &path) const {}

std::string ChunkActionAuthority::Version(const std::string &name,
                                          const std::string &content) const {}

std::string ChunkActionAuthority::Version(const std::string &name,
                                          const fs::path &path) const {}

}  // namespace priv

}  // namespace maidsafe

