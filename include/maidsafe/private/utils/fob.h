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

#ifndef MAIDSAFE_PRIVATE_UTILS_FOB_H_
#define MAIDSAFE_PRIVATE_UTILS_FOB_H_

#include <vector>

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

namespace maidsafe {

struct Fob {
  Fob();
  Identity identity;
  asymm::Keys keys;
  NonEmptyString validation_token;
};

namespace priv {

namespace utils {

// Generates the identity according to the maidsafe patent
Fob GenerateFob(asymm::PrivateKey* private_key);

// Generates chained identities according to the maidsafe patent
std::vector<Fob> GenerateChainedFob(size_t amount, asymm::PrivateKey* private_key);

// Validates identity according to the maidsafe patent
bool ValidateFob(const Fob& fob, asymm::PrivateKey* private_key);

// Serialise the fob using protocol buffers
NonEmptyString SerialiseFob(const Fob& fob);

// Parse a serialised protocol buffer to a fob
Fob ParseFob(const NonEmptyString& serialised_fob);

}  // namespace utils

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_UTILS_FOB_H_
