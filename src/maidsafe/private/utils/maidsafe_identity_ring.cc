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

#include "maidsafe/private/utils/maidsafe_identity_ring.h"

#include "maidsafe/common/error.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/utils/identity_ring_pb.h"

namespace maidsafe {

namespace priv {

namespace utilities {

MaidsafeIdentityRing::MaidsafeIdentityRing()
    : identity(),
      keys(),
      validation_token() {}

// Generates the identity according to the maidsafe patent
MaidsafeIdentityRing GenerateIdentityRing(asymm::PrivateKey* private_key) {
  MaidsafeIdentityRing identity_ring;
  identity_ring.keys = asymm::GenerateKeyPair();

  asymm::PrivateKey signing_private_key;
  if (private_key)
    signing_private_key = *private_key;
  else
    signing_private_key = identity_ring.keys.private_key;

  asymm::EncodedPublicKey encoded_public_key(asymm::EncodeKey(identity_ring.keys.public_key));

  identity_ring.validation_token = asymm::Sign(asymm::PlainText(encoded_public_key.string()),
                                               identity_ring.keys.private_key);
  identity_ring.identity = crypto::Hash<crypto::SHA512>(encoded_public_key.string() +
                                                        identity_ring.validation_token.string());
  return identity_ring;
}

// Generates chained identities according to the maidsafe patent
std::vector<MaidsafeIdentityRing> GenerateChainedIdentityRing(size_t amount,
                                                              asymm::PrivateKey* private_key) {
  assert(amount > 1U);

  std::vector<MaidsafeIdentityRing> identity_chain;
  identity_chain.push_back(GenerateIdentityRing(private_key));
  for (size_t n(1); n < amount; ++n)
    identity_chain.push_back(GenerateIdentityRing(&(identity_chain.at(n - 1).keys.private_key)));

  return identity_chain;
}

// Serialise the identity ring using protocol buffers
NonEmptyString SerialiseMaidsafeIdentityRing(const MaidsafeIdentityRing& identity_ring) {
  protobuf::MaidsafeIdentityRing proto_ring;
  proto_ring.set_identity(identity_ring.identity.string());
  proto_ring.set_validation_token(identity_ring.validation_token.string());
  asymm::EncodedPublicKey encoded_public(asymm::EncodeKey(identity_ring.keys.public_key));
  asymm::EncodedPrivateKey encoded_private(asymm::EncodeKey(identity_ring.keys.private_key));
  proto_ring.set_encoded_public_key(encoded_public.string());
  proto_ring.set_encoded_private_key(encoded_private.string());

  std::string result(proto_ring.SerializeAsString());
  if (result.empty())
    ThrowError(MaidsafeIdentityRingErrors::ring_serialisation_error);

  return NonEmptyString(result);
}

// Parse a serialised protocol buffer to an identity ring
MaidsafeIdentityRing ParseMaidsafeIdentityRing(const NonEmptyString& serialised_identity_ring) {
  protobuf::MaidsafeIdentityRing proto_ring;
  if (!proto_ring.ParseFromString(serialised_identity_ring.string()))
    ThrowError(MaidsafeIdentityRingErrors::ring_parsing_error);

  MaidsafeIdentityRing identity_ring;
  identity_ring.identity = Identity(proto_ring.identity());
  identity_ring.validation_token = NonEmptyString(proto_ring.validation_token());
  identity_ring.keys.public_key =
      asymm::DecodeKey(asymm::EncodedPublicKey(proto_ring.encoded_public_key()));
  identity_ring.keys.private_key =
      asymm::DecodeKey(asymm::EncodedPrivateKey(proto_ring.encoded_private_key()));
  return identity_ring;
}

}  // namespace utilities

}  // namespace priv

}  // namespace maidsafe
