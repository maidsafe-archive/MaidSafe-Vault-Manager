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
#include "maidsafe/data_types/immutable_data.h"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"


namespace maidsafe {

const DataTagValue ImmutableDataTag::kEnumValue = DataTagValue::kImmutableDataValue;

ImmutableData::ImmutableData(const ImmutableData& other) : name_(other.name_), data_(other.data_) {}

ImmutableData& ImmutableData::operator=(const ImmutableData& other) {
  name_ = other.name_;
  data_ = other.data_;
  return *this;
}

ImmutableData::ImmutableData(ImmutableData&& other)
    : name_(std::move(other.name_)),
      data_(std::move(other.data_)) {}

ImmutableData& ImmutableData::operator=(ImmutableData&& other) {
  name_ = std::move(other.name_);
  data_ = std::move(other.data_);
  return *this;
}

ImmutableData::ImmutableData(const NonEmptyString& content)
    : name_(name_type(crypto::Hash<crypto::SHA512>(content))),
      data_(content) {}

ImmutableData::ImmutableData(const name_type& name,
                             const serialised_type& serialised_immutable_data)
    : name_(name),
      data_(serialised_immutable_data.data) {
  Validate();
}

void ImmutableData::Validate() const {
  if (name_.data != crypto::Hash<crypto::SHA512>(data_))
    ThrowError(CommonErrors::hashing_error);
}

ImmutableData::serialised_type ImmutableData::Serialise() const {
  return serialised_type(data_);
}

}  // namespace maidsafe
