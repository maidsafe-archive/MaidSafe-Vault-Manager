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

#include "maidsafe/common/chunk_action_authority.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/version.h"

#if MAIDSAFE_PRIVATE_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif

namespace fs = boost::filesystem;


namespace maidsafe {

class ChunkStore;


namespace priv {

namespace chunk_actions {

class Chunk;

unsigned char GetDataType(const std::string &name);

template <typename T>
bool ParseProtobuf(const std::string &serialised_data, T *protobuf_type);

template <typename T>
int DeleteIfOwner(const std::string &name,
                  const std::string &version,
                  const asymm::PublicKey &public_key,
                  std::shared_ptr<ChunkStore> chunk_store);

//int ProcessSignedData(const ChunkActionAuthority::OperationType &op_type,
//                      const std::string &name,
//                      const std::string &data,
//                      const asymm::PublicKey &public_key,
//                      const bool &hashable,
//                      std::shared_ptr<ChunkStore> chunk_store,
//                      std::string *new_content);
//
//int PreOperationChecks(const ChunkActionAuthority::OperationType &op_type,
//                       const std::string &name,
//                       const std::string &data,
//                       const asymm::PublicKey &public_key,
//                       const bool &hashable);
//
//int VerifyCurrentData(const std::string &name,
//                      const asymm::PublicKey &public_key,
//                      std::shared_ptr<ChunkStore> chunk_store,
//                      std::string *existing_data);

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_UTILS_H_
