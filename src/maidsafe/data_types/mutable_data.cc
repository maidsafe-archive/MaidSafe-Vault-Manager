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
#include "maidsafe/data_types/mutable_data.h"

#include "maidsafe/common/types.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"

#include "maidsafe/data_types/mutable_data_pb.h"


namespace maidsafe {

MutableData::MutableData(const MutableData& other)
    : name_(other.name_),
      data_(other.data_),
      signature_(other.signature_),
      version_(other.version_) {}

MutableData& MutableData::operator=(const MutableData& other) {
  name_ = other.name_;
  data_ = other.data_;
  signature_ = other.signature_;
  version_ = other.version_;
  return *this;
}

MutableData::MutableData(MutableData&& other)
    : name_(std::move(other.name_)),
      data_(std::move(other.data_)),
      signature_(std::move(other.signature_)),
      version_(std::move(other.version_)) {}

MutableData& MutableData::operator=(MutableData&& other) {
  name_ = std::move(other.name_);
  data_ = std::move(other.data_);
  signature_ = std::move(other.signature_);
  version_ = std::move(other.version_);
  return *this;
}

MutableData::MutableData(const name_type& name,
                         const NonEmptyString& data,
                         const asymm::Signature& signature,
                         int32_t version)
    : name_(name),
      data_(data),
      signature_(signature),
      version_(version) {}

MutableData::MutableData(const name_type& name, const serialised_type& serialised_mutable_data)
    : name_(name),
      data_(),
      signature_(),
      version_(0) {
  protobuf::MutableData proto_mutable_data;
  // TODO(Fraser#5#): 2012-12-29 - Add PrivateErrors to Common and use here
  if (!proto_mutable_data.ParseFromString(serialised_mutable_data.data.string()))
    ThrowError(CommonErrors::invalid_parameter);
  data_ = NonEmptyString(proto_mutable_data.data());
  if (proto_mutable_data.has_signature())
    signature_ = asymm::Signature(proto_mutable_data.signature());
  if (proto_mutable_data.has_version())
    version_ = proto_mutable_data.version();
}

MutableData::serialised_type MutableData::Serialise() const {
  protobuf::MutableData proto_mutable_data;
  proto_mutable_data.set_data(data_.string());
  if (signature_.IsInitialised())
    proto_mutable_data.set_signature(signature_.string());
  proto_mutable_data.set_version(version_);
  return serialised_type(NonEmptyString(proto_mutable_data.SerializeAsString()));
}

}  // namespace maidsafe

