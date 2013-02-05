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

typedef boost::variant<passport::PublicAnmid::name_type,
                       passport::PublicAnsmid::name_type,
                       passport::PublicAntmid::name_type,
                       passport::PublicAnmaid::name_type,
                       passport::PublicMaid::name_type,
                       passport::PublicPmid::name_type,
                       passport::Mid::name_type,
                       passport::Smid::name_type,
                       passport::Tmid::name_type,
                       passport::PublicAnmpid::name_type,
                       passport::PublicMpid::name_type,
                       ImmutableData::name_type,
                       OwnerDirectory::name_type,
                       GroupDirectory::name_type,
                       WorldDirectory::name_type> DataNameVariant;


inline DataNameVariant GetDataNameVariant(DataTagValue type, const Identity& name) {
  switch (type) {
    case DataTagValue::kAnmidValue: return passport::PublicAnmid::name_type(name);
    case DataTagValue::kAnsmidValue: return passport::PublicAnsmid::name_type(name);
    case DataTagValue::kAntmidValue: return passport::PublicAntmid::name_type(name);
    case DataTagValue::kAnmaidValue: return passport::PublicAnmaid::name_type(name);
    case DataTagValue::kMaidValue: return passport::PublicMaid::name_type(name);
    case DataTagValue::kPmidValue: return passport::PublicPmid::name_type(name);
    case DataTagValue::kMidValue: return passport::Mid::name_type(name);
    case DataTagValue::kSmidValue: return passport::Smid::name_type(name);
    case DataTagValue::kTmidValue: return passport::Tmid::name_type(name);
    case DataTagValue::kAnmpidValue: return passport::PublicAnmpid::name_type(name);
    case DataTagValue::kMpidValue: return passport::PublicMpid::name_type(name);
    case DataTagValue::kImmutableDataValue: return ImmutableData::name_type(name);
    case DataTagValue::kOwnerDirectoryValue: return OwnerDirectory::name_type(name);
    case DataTagValue::kGroupDirectoryValue: return GroupDirectory::name_type(name);
    case DataTagValue::kWorldDirectoryValue: return WorldDirectory::name_type(name);
    default: {
      LOG(kError) << "Unhandled data type";
      ThrowError(CommonErrors::invalid_parameter);
      return DataNameVariant();
    }
  }
}

struct GetTagValueVisitor : public boost::static_visitor<DataTagValue> {
  template<typename T, typename Tag>
  result_type operator()(const TaggedValue<T, Tag>&) const {
    return TaggedValue<T, Tag>::tag_type::kEnumValue;
  }
};

struct GetIdentityVisitor : public boost::static_visitor<Identity> {
  template<typename T, typename Tag>
  result_type operator()(const TaggedValue<T, Tag>& t) const {
    return t.data;
  }
};

struct GetTagValueAndIdentityVisitor
    : public boost::static_visitor<std::pair<DataTagValue, Identity>> {
  template<typename T, typename Tag>
  result_type operator()(const TaggedValue<T, Tag>& t) const {
    return std::make_pair(TaggedValue<T, Tag>::tag_type::kEnumValue, t.data);
  }
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_DATA_NAME_VARIANT_H_
