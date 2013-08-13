/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_DATA_TYPES_DATA_NAME_VARIANT_H_
#define MAIDSAFE_DATA_TYPES_DATA_NAME_VARIANT_H_

#include <type_traits>
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
                       ImmutableData::Name,
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
    case DataTagValue::kImmutableDataValue: return ImmutableData::Name(name);
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



template<DataTagValue tag_value, typename Enable = void>
struct is_maidsafe_data {
  static const bool value = false;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kAnmidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::PublicAnmid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kAnsmidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::PublicAnsmid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kAntmidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::PublicAntmid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kAnmaidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::PublicAnmaid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kMaidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::PublicMaid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kPmidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::PublicPmid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kMidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::Mid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kSmidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::Smid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kTmidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::Tmid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kAnmpidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::PublicAnmpid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue, DataTagValue::kMpidValue>>::value>::type> {
  static const bool value = true;
  typedef passport::PublicMpid data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue,
                                   DataTagValue::kImmutableDataValue>>::value>::type> {
  static const bool value = true;
  typedef ImmutableData data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue,
                                   DataTagValue::kOwnerDirectoryValue>>::value>::type> {
  static const bool value = true;
  typedef OwnerDirectory data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue,
                                   DataTagValue::kGroupDirectoryValue>>::value>::type> {
  static const bool value = true;
  typedef GroupDirectory data_type;
  typedef data_type::name_type name_type;
};

template<DataTagValue tag_value>
struct is_maidsafe_data<tag_value,
    typename std::enable_if<
        std::is_same<
            std::integral_constant<DataTagValue, tag_value>,
            std::integral_constant<DataTagValue,
                                   DataTagValue::kWorldDirectoryValue>>::value>::type> {
  static const bool value = true;
  typedef WorldDirectory data_type;
  typedef data_type::name_type name_type;
};



template<DataTagValue tag_value>
typename std::enable_if<
    is_maidsafe_data<tag_value>::value,
    typename is_maidsafe_data<tag_value>::name_type>::type GetName(const Identity& name) {
  return typename is_maidsafe_data<tag_value>::name_type(name);
}

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_DATA_NAME_VARIANT_H_
