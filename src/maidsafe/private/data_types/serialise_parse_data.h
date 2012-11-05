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

#ifndef MAIDSAFE_PRIVATE_DATA_MANAGER_SERIALISE_PARSE_DATA_H_
#define MAIDSAFE_PRIVATE_DATA_MANAGER_SERIALISE_PARSE_DATA_H_

#include "maidsafe/private/"

// this can all go in a cc file
// Default, hash of content == name
ImmutableData CreateDataType(const ChunkId name,const NonEmptyString content) {
  // .... do stuff to check
  // this probably a try catch block !!
  return ImmutableData(const ChunkId name,const NonEmptyString content);
}

// Signature, (hash of content + sig == name) !! (content == 0 and signed)
SignatureData CreateDataType(const ChunkId name,
                             const asymm::PublicKey content,
                             const Signature signature,
                             const asymm::PublicKey public_key);
// Edit by owner
MutableData signatureData CreateDataType(const ChunkId name,
                                         const NonEmptyString content,
                                         const Signature signature,
                                         const asymm::PublicKey public_key);
// Appendable by all
AppendableData CreateDataType(const ChunkId name,
                              const NonEmptyString content,
                              const std::vector<asymm::PublicKey> allowed,
                              const Signature signature,
                              const asymm::PublicKey public_key);


#endif  // MAIDSAFE_PRIVATE_DATA_MANAGER_H_

