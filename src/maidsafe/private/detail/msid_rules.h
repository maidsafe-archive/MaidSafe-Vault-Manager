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

#ifndef MAIDSAFE_PRIVATE_DETAIL_MSID_RULES_H_
#define MAIDSAFE_PRIVATE_DETAIL_MSID_RULES_H_

#include "maidsafe/private/detail/utils.h"


namespace maidsafe {

namespace priv {

const unsigned char kMsidData(4);  // Chunk type

// Whether this type can be cached or not.
template<> bool Cacheable<kMsidData>() { return false; }


namespace detail {

template<>
int ProcessData<kMsidData>(const int &op_type,
                           const std::string &name,
                           const std::string &content,
                           const asymm::PublicKey &public_key,
                           std::shared_ptr<ChunkStore> chunk_store,
                           std::string *new_content);

template<>
int ProcessData<kMsidData>(const int &op_type,
                           const std::string &name,
                           const fs::path &path,
                           const asymm::PublicKey &public_key,
                           std::shared_ptr<ChunkStore> chunk_store,
                           std::string *new_content);

}  // namespace detail

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DETAIL_MSID_RULES_H_
