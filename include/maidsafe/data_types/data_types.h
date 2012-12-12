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
#include "maidsafe/common/tagged_value.h"

namespace maidsafe {

class ImmutableData {
 public:
  typedef TaggedValue<Identity, struct ImmutableDataTag> name_type;
  ImmutableData(const name_type& name, const NonEmptyString& content);
  ImmutableData(const NonEmptyString& serialised_data);
  NonEmptyString Serialise() const;
  name_type name() const;
 private:
  void Validate();
  NonEmptyString data_;
  name_type name_;
};

class MutableData {
 public:
  typedef TaggedValue<Identity, struct MutableDataTag> name_type;
  MutableData(const name_type& name,
              const NonEmptyString& content,
              const asymm::Signature& signature,
              const asymm::PublicKey& validation_key);
  MutableData(const NonEmptyString& serialised_data);
  NonEmptyString Serialise() const;
  name_type name() const;
  int32_t version() const;  // use randomint32 as faster than hash
 private:
  void Validate();
  NonEmptyString data_;
  name_type name_;
  asymm::Signature signature_;
  int32_t version_;
};

class SignatureData {
 public:
  typedef TaggedValue<Identity, struct SignatureDataTag> name_type;
  SignatureData(const name_type& name,
                const asymm::PublicKey& content,
                const asymm::Signature& signature,
                const asymm::PublicKey& validation_key);
  SignatureData(const NonEmptyString& serialised_data);
  NonEmptyString Serialise() const;
  name_type name() const;
  int32_t version() const;  // use randomint32 as faster than hash

 private:
  void Validate();
  NonEmptyString data_;
  name_type name_;
  int32_t version_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DATA_TYPES_DATA_TYPES_H_

