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

#include "maidsafe/private/chunk_actions/utils.h"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"

#include "maidsafe/private/chunk_store/chunk_store.h"


namespace maidsafe {

namespace priv {

namespace chunk_actions {

namespace detail {

void GetContentAndTigerHash(const ChunkId& name,
                            std::shared_ptr<chunk_store::ChunkStore> chunk_store,
                            std::string& chunk_content,
                            crypto::TigerHash& hash) {
  chunk_content = chunk_store->Get(name);
  if (chunk_content.empty()) {
    LOG(kError) << "GetContentAndTigerHash - Failed to retrieve " << Base32Substr(name);
    hash = crypto::TigerHash();
  } else {
    hash = crypto::Hash<crypto::Tiger>(chunk_content);
  }
}

}  // namespace detail

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

