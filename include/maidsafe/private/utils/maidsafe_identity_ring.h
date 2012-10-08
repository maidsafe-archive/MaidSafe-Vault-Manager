/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#ifndef MAIDSAFE_PRIVATE_UTILS_MAIDSAFE_IDENTITY_RING_H
#define MAIDSAFE_PRIVATE_UTILS_MAIDSAFE_IDENTITY_RING_H

#include <vector>

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

namespace maidsafe {

namespace priv {

namespace utilities {

struct MaidsafeIdentityRing {
  MaidsafeIdentityRing();
  Identity identity;
  asymm::Keys keys;
  NonEmptyString validation_token;
};

// Generates the identity according to the maidsafe patent
MaidsafeIdentityRing GenerateIdentityRing(asymm::PrivateKey* private_key = nullptr);

// Generates chained identities according to the maidsafe patent
std::vector<MaidsafeIdentityRing> GenerateChainedIdentityRing(
    size_t amount,
    asymm::PrivateKey* private_key = nullptr);

// Serialise the identity ring using protocol buffers

NonEmptyString SerialiseMaidsafeIdentityRing(const MaidsafeIdentityRing& identity_ring);

// Parse a serialised protocol buffer to an identity ring
MaidsafeIdentityRing ParseMaidsafeIdentityRing(const NonEmptyString& serialised_identity_ring);

}  // namespace utilities

}  // namespace priv

}  // namespace maidsafe

#endif // MAIDSAFE_PRIVATE_UTILS_MAIDSAFE_IDENTITY_RING_H
