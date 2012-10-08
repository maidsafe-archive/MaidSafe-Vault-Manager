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

#include "maidsafe/private/utils/fob.h"

#include "maidsafe/common/error.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/utils/fob_pb.h"

namespace maidsafe {

Fob::Fob() : identity(), keys(), validation_token() {}

namespace priv {

namespace utilities {

Fob GenerateFob(asymm::PrivateKey* private_key) {
  Fob fob;
  fob.keys = asymm::GenerateKeyPair();

  asymm::PrivateKey signing_private_key;
  if (private_key)
    signing_private_key = *private_key;
  else
    signing_private_key = fob.keys.private_key;

  asymm::EncodedPublicKey encoded_public_key(asymm::EncodeKey(fob.keys.public_key));
  fob.validation_token = asymm::Sign(asymm::PlainText(encoded_public_key.string()),
                                     fob.keys.private_key);
  fob.identity = crypto::Hash<crypto::SHA512>(encoded_public_key.string() +
                                              fob.validation_token.string());
  return fob;
}

std::vector<Fob> GenerateChainedFob(size_t amount, asymm::PrivateKey* private_key) {
  assert(amount > 1U);

  std::vector<Fob> fob_chain;
  fob_chain.push_back(GenerateFob(private_key));
  for (size_t n(1); n < amount; ++n)
    fob_chain.push_back(GenerateFob(&(fob_chain.at(n - 1).keys.private_key)));

  return fob_chain;
}

NonEmptyString SerialiseFob(const Fob& fob) {
  protobuf::Fob proto_fob;
  proto_fob.set_identity(fob.identity.string());
  proto_fob.set_validation_token(fob.validation_token.string());
  asymm::EncodedPublicKey encoded_public(asymm::EncodeKey(fob.keys.public_key));
  asymm::EncodedPrivateKey encoded_private(asymm::EncodeKey(fob.keys.private_key));
  proto_fob.set_encoded_public_key(encoded_public.string());
  proto_fob.set_encoded_private_key(encoded_private.string());

  std::string result(proto_fob.SerializeAsString());
  if (result.empty())
    ThrowError(FobErrors::fob_serialisation_error);

  return NonEmptyString(result);
}

Fob ParseFob(const NonEmptyString& serialised_fob) {
  protobuf::Fob proto_fob;
  if (!proto_fob.ParseFromString(serialised_fob.string()))
    ThrowError(FobErrors::fob_parsing_error);

  Fob fob;
  fob.identity = Identity(proto_fob.identity());
  fob.validation_token = NonEmptyString(proto_fob.validation_token());
  fob.keys.public_key = asymm::DecodeKey(asymm::EncodedPublicKey(proto_fob.encoded_public_key()));
  fob.keys.private_key =
      asymm::DecodeKey(asymm::EncodedPrivateKey(proto_fob.encoded_private_key()));
  return fob;
}

}  // namespace utilities

}  // namespace priv

}  // namespace maidsafe
