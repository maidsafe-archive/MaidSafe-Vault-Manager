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

#include "maidsafe/data_types/data_pb.h"

namespace maidsafe {

MutableData::MutableData(const name_type& /*name*/,
                         const NonEmptyString& /*content*/,
                         const asymm::Signature& /*signature*/,
                         const asymm::PublicKey& /*validation_key*/) {}

MutableData::MutableData(const NonEmptyString& /*serialised_data*/) {}

NonEmptyString MutableData::Serialise() const {
  data_types::proto::Content data_proto;
  data_proto.set_data(data_.string());
  data_proto.set_signature(signature_.string());
  data_proto.set_version(boost::lexical_cast<std::string>(version_));
  return NonEmptyString(data_proto.SerializeAsString());
}

MutableData::name_type MutableData::name() const { return name_; }

int32_t MutableData::version() const { return version_; }

}  // namespace maidsafe

