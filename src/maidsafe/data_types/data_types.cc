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
#include "maidsafe/data_types/data_types.h"

#include "maidsafe/common/types.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"
#include "maidsafe/data_types/data.pb.h"

namespace maidsafe {

ImmutableData::ImmutableData(const name_type& name, const NonEmptyString& content)
  : data_(content), name_(name) {
    Validate();
}

ImmutableData::ImmutableData(const NonEmptyString& serialised_data) : data_(), name_() {
   data_types::proto::Content data_proto;
   data_proto.ParseFromString(serialised_data.string());
//   name_ = Identity(data_proto.name());
//   data_ = NonEmptyString(data_proto.content().data());
   Validate();
}

void ImmutableData::Validate() {
// if (name_ != crypto::Hash<crypto::SHA512>(data_))
//   ThrowError(CommonErrors::hashing_error);
}

ImmutableData::name_type ImmutableData::name() const {
  return name_;
}

NonEmptyString ImmutableData::Serialise() const {
   data_types::proto::Content data_proto;
//   data_types::proto::Content content_proto;
//   data_proto.set_type(priv::data_types::proto::kDataType::ImmutableData);
//   data_proto.set_name(name_.string());
//   content_proto.set_data(data_.string());
//   data_proto.mutable_content()->CopyFrom(content_proto);
   return NonEmptyString(data_proto.SerializeAsString());
}

//TODO implement these!! 
// 
// class MutableData {
//  public:
//   MutableData(const priv::ChunkId name,
//               const NonEmptyString content,
//               const rsa::Signature signature);
//   MutableData(const NonEmptyString serialised_data);
//   NonEmptyString Serialise();
//   Identity name();
//   NonEmptyString version();
//  private:
//   bool Validate();
//   NonEmptyString data_;
//   Identity name_;
// };
// 
// class rsa::SignatureData {
//  public:
//   rsa::SignatureData(const priv::ChunkId name,
//               const asymm::PublicKey content,
//               const rsa::Signature signature);
//   rsa::SignatureData(const NonEmptyString serialised_data);
//   NonEmptyString Serialise();
//   Identity name();
//   NonEmptyString version();
//  private:
//   bool Validate();
//   NonEmptyString data_;
//   Identity name_;
// };
// 
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
//   bool Validate();
//   NonEmptyString data_;
//   Identity name_;
// };

}  // namespace maidsafe

