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

// This object is immutable by design, it does not allow any alteration after construction.
class Fob {
 public:
  Fob();
  Fob(Identity signed_by, asymm::PrivateKey private_key);
  Fob(Identity identity,
      asymm::PublicKey public_key,
      asymm::PrivateKey private_key,
      asymm::Signature validation_token);
  Fob(Identity identity,
      asymm::PublicKey public_key,
      asymm::PrivateKey private_key,
      asymm::Signature validation_token,
      Identity signed_by,
      asymm::PrivateKey signed_by_private_key);
  Identity identity() const;
  asymm::PublicKey public_key() const;
  asymm::PrivateKey private_key() const;
  asymm::Signature validation_token() const;
  Identity signed_by() const;

 private:
  asymm::Signature CreateValidation();
  asymm::Signature CreateChainedValidation(const asymm::PrivateKey& private_key);
  Identity CreateIdentity();
  void CreateKeys();

  Identity identity_;
  asymm::PublicKey public_key_;
  asymm::PrivateKey private_key_;
  asymm::Signature validation_token_;
  Identity signed_by_;
};

// Serialise the fob using protocol buffers
NonEmptyString SerialiseFob(const Fob& fob);

// Parse a serialised protocol buffer to a fob
Fob ParseFob(const NonEmptyString& serialised_fob);

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_UTILS_FOB_H_
