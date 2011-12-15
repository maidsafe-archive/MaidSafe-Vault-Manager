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

#include "maidsafe/private/detail/mcid_rules.h"

#include "maidsafe/common/chunk_action_authority.h"
#include "maidsafe/common/chunk_store.h"

#include "maidsafe/private/chunk_messages_pb.h"
#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"


namespace maidsafe {

namespace priv {

namespace detail {

template<>
int ProcessData<kMcidData>(const int &op_type,
                           const std::string &name,
                           const std::string &content,
                           const asymm::PublicKey &public_key,
                           std::shared_ptr<ChunkStore> chunk_store,
                           std::string *new_content) {

}

template<>
int ProcessData<kMcidData>(const int &op_type,
                           const std::string &name,
                           const fs::path &path,
                           const asymm::PublicKey &public_key,
                           std::shared_ptr<ChunkStore> chunk_store,
                           std::string *new_content) {
}

}  // namespace detail

}  // namespace priv

}  // namespace maidsafe
