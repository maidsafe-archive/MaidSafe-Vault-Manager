/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_DATA_TYPES_DATA_NAME_VARIANT_H_
#define MAIDSAFE_DATA_TYPES_DATA_NAME_VARIANT_H_

#include <utility>

#include "boost/variant/static_visitor.hpp"
#include "boost/variant/variant.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/data_types/data_type_values.h"
#include "maidsafe/data_types/immutable_data.h"
#include "maidsafe/data_types/owner_directory.h"
#include "maidsafe/data_types/group_directory.h"
#include "maidsafe/data_types/world_directory.h"

namespace maidsafe {

typedef boost::variant<passport::PublicAnmid::Name, passport::PublicAnsmid::Name,
                       passport::PublicAntmid::Name, passport::PublicAnmaid::Name,
                       passport::PublicMaid::Name, passport::PublicPmid::Name, passport::Mid::Name,
                       passport::Smid::Name, passport::Tmid::Name, passport::PublicAnmpid::Name,
                       passport::PublicMpid::Name, ImmutableData::Name, OwnerDirectory::Name,
                       GroupDirectory::Name, WorldDirectory::Name> DataNameVariant;

inline DataNameVariant GetDataNameVariant(DataTagValue type, const Identity& name) {
  switch (type) {
    case DataTagValue::kAnmidValue:
      return passport::PublicAnmid::Name(name);
    case DataTagValue::kAnsmidValue:
      return passport::PublicAnsmid::Name(name);
    case DataTagValue::kAntmidValue:
      return passport::PublicAntmid::Name(name);
    case DataTagValue::kAnmaidValue:
      return passport::PublicAnmaid::Name(name);
    case DataTagValue::kMaidValue:
      return passport::PublicMaid::Name(name);
    case DataTagValue::kPmidValue:
      return passport::PublicPmid::Name(name);
    case DataTagValue::kMidValue:
      return passport::Mid::Name(name);
    case DataTagValue::kSmidValue:
      return passport::Smid::Name(name);
    case DataTagValue::kTmidValue:
      return passport::Tmid::Name(name);
    case DataTagValue::kAnmpidValue:
      return passport::PublicAnmpid::Name(name);
    case DataTagValue::kMpidValue:
      return passport::PublicMpid::Name(name);
    case DataTagValue::kImmutableDataValue:
      return ImmutableData::Name(name);
    case DataTagValue::kOwnerDirectoryValue:
      return OwnerDirectory::Name(name);
    case DataTagValue::kGroupDirectoryValue:
      return GroupDirectory::Name(name);
    case DataTagValue::kWorldDirectoryValue:
      return WorldDirectory::Name(name);
    default: {
      LOG(kError) << "Unhandled data type";
      ThrowError(CommonErrors::invalid_parameter);
      return DataNameVariant();
    }
  }
}

struct GetTagValueVisitor : public boost::static_visitor<DataTagValue> {
  template <typename NameType>
  result_type operator()(const NameType&) const {
    return NameType::data_type::Tag::kValue;
  }
};

struct GetIdentityVisitor : public boost::static_visitor<Identity> {
  template <typename NameType>
  result_type operator()(const NameType& name) const {
    return name.value;
  }
};

struct GetTagValueAndIdentityVisitor
    : public boost::static_visitor<std::pair<DataTagValue, Identity>> {
  template <typename NameType>
  result_type operator()(const NameType& name) const {
    return std::make_pair(NameType::data_type::Tag::kValue, name.value);
  }
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_DATA_NAME_VARIANT_H_
