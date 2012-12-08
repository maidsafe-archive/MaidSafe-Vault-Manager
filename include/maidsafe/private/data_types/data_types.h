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

#ifndef MAIDSAFE_PRIVATE_DATA_TYPES_DATA_TYPES_H_
#define MAIDSAFE_PRIVATE_DATA_TYPES_DATA_TYPES_H_

#include "maidsafe/common/types.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/private/chunk_actions/chunk_id.h"

namespace maidsafe {

class ImmutableData {
 public:
  ImmutableData(const priv::ChunkId name, const NonEmptyString& content);
  ImmutableData(const NonEmptyString& serialised_data);
  NonEmptyString Serialise();
  Identity name();
 private:
  void Validate();
  NonEmptyString data_;
  Identity name_;
};

class MutableData {
 public:
  MutableData(const priv::ChunkId name,
              const NonEmptyString content,
              const rsa::Signature signature);
  MutableData(const NonEmptyString serialised_data);
  NonEmptyString Serialise();
  Identity name();
  NonEmptyString version();
 private:
  void Validate();
  NonEmptyString data_;
  Identity name_;
  rsa::Signature signature_;
};

class SignatureData {
 public:
  SignatureData(const priv::ChunkId name,
                const asymm::PublicKey content,
                const rsa::Signature signature);
  SignatureData(const NonEmptyString serialised_data);
  NonEmptyString Serialise();
  Identity name();
  NonEmptyString version();
 private:
  void Validate();
  NonEmptyString data_;
  Identity name_;
};

// This will be factored out 
// class AppendableData {
//  public:
//   AppendableData(const priv::ChunkId name,
//               const NonEmptyString content,
//               const std::vector<asymm::PublicKey> allowed,
//               const rsa::Signature signature);
//   AppendableData(const NonEmptyString serialised_data);
//   NonEmptyString Serialise();
//   Identity name();
//   NonEmptyString version();
//  private:
//   void Validate();
//   NonEmptyString data_;
//   Identity name_;
// };

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DATA_TYPES_DATA_TYPES_H_

