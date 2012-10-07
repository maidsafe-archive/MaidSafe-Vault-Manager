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

#ifndef MAIDSAFE_PRIVATE_CHUNK_ACTIONS_UTILS_H_
#define MAIDSAFE_PRIVATE_CHUNK_ACTIONS_UTILS_H_

#include <memory>
#include <string>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/chunk_actions/chunk_type.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_store { class ChunkStore; }

namespace chunk_actions {

namespace detail {

template <typename T>
bool ParseProtobuf(const std::string& serialised_data, T* protobuf_type);

void GetContentAndTigerHash(const ChunkId& name,
                            std::shared_ptr<chunk_store::ChunkStore> chunk_store,
                            std::string& chunk_content,
                            crypto::TigerHash& hash);


template <typename T>
bool ParseProtobuf(const std::string& serialised_data, T* protobuf_type) {
  try {
    if (!protobuf_type->ParseFromString(serialised_data)) {
      LOG(kError) << "ParseProtobuf - Failed to parse.";
      return false;
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << "ParseProtobuf - Failed to parse: " << e.what();
    return false;
  }
  return true;
}

}  // namespace detail

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_UTILS_H_
