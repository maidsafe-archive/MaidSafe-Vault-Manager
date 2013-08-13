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

#ifndef MAIDSAFE_DATA_TYPES_DATA_TYPE_VALUES_H_
#define MAIDSAFE_DATA_TYPES_DATA_TYPE_VALUES_H_

#include <cstdint>
#include <ostream>
#include <string>

#include "maidsafe/common/types.h"


namespace maidsafe {

enum class DataTagValue : uint32_t {
  kAnmidValue,
  kAnsmidValue,
  kAntmidValue,
  kAnmaidValue,
  kMaidValue,
  kPmidValue,
  kMidValue,
  kSmidValue,
  kTmidValue,
  kAnmpidValue,
  kMpidValue,
  kImmutableDataValue,
  kOwnerDirectoryValue,
  kGroupDirectoryValue,
  kWorldDirectoryValue
};


template <typename Elem, typename Traits>
std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& ostream,
                                             const DataTagValue &data_type) {
  std::string data_type_str;
  switch (data_type) {
    case DataTagValue::kAnmidValue:
      data_type_str = "ANMID";
      break;
    case DataTagValue::kAnsmidValue:
      data_type_str = "ANSMID";
      break;
    case DataTagValue::kAntmidValue:
      data_type_str = "ANTMID";
      break;
    case DataTagValue::kAnmaidValue:
      data_type_str = "ANMAID";
      break;
    case DataTagValue::kMaidValue:
      data_type_str = "MAID";
      break;
    case DataTagValue::kPmidValue:
      data_type_str = "PMID";
      break;
    case DataTagValue::kMidValue:
      data_type_str = "MID";
      break;
    case DataTagValue::kSmidValue:
      data_type_str = "SMID";
      break;
    case DataTagValue::kTmidValue:
      data_type_str = "TMID";
      break;
    case DataTagValue::kAnmpidValue:
      data_type_str = "ANMPID";
      break;
    case DataTagValue::kMpidValue:
      data_type_str = "MPID";
      break;
    case DataTagValue::kImmutableDataValue:
      data_type_str = "Immutable Data";
      break;
    case DataTagValue::kOwnerDirectoryValue:
      data_type_str = "Owner Directory";
      break;
    case DataTagValue::kGroupDirectoryValue:
      data_type_str = "Group Directory";
      break;
    case DataTagValue::kWorldDirectoryValue:
      data_type_str = "World Directory";
      break;
    default:
      data_type_str = "Invalid data type";
      break;
  }

  for (std::string::iterator itr(data_type_str.begin()); itr != data_type_str.end(); ++itr)
    ostream << ostream.widen(*itr);
  return ostream;
}

namespace detail {

template<typename Parent>
struct Name {
  Name() : value() {}
  explicit Name(const Identity& value_in) : value(value_in) {}
  explicit Name(Identity&& value_in) : value(std::move(value_in)) {}
  Name(const Name& other) : value(other.value) {}
  Name(Name&& other) : value(std::move(other.value)) {}
  Name& operator=(Name other);

  operator Identity() const { return value; }
  Identity const* operator->() const { return &value; }
  Identity* operator->() { return &value; }

  Identity value;
  typedef Parent data_type;
};

template<typename Parent>
void swap(Name<Parent>& lhs, Name<Parent>& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.value, rhs.value);
}

template<typename Parent>
Name<Parent>& Name<Parent>::operator=(Name<Parent> other) {
  swap(*this, other);
  return *this;
}

template<typename Parent>
inline bool operator==(const Name<Parent>& lhs, const Name<Parent>& rhs) {
  return lhs.value == rhs.value;
}

template<typename Parent>
inline bool operator!=(const Name<Parent>& lhs, const Name<Parent>& rhs) {
  return !operator==(lhs, rhs);
}

template<typename Parent>
inline bool operator<(const Name<Parent>& lhs, const Name<Parent>& rhs) {
  return lhs.value < rhs.value;
}

template<typename Parent>
inline bool operator>(const Name<Parent>& lhs, const Name<Parent>& rhs) {
  return operator<(rhs, lhs);
}

template<typename Parent>
inline bool operator<=(const Name<Parent>& lhs, const Name<Parent>& rhs) {
  return return !operator>(lhs, rhs);
}

template<typename Parent>
inline bool operator>=(const Name<Parent>& lhs, const Name<Parent>& rhs) {
  return !operator<(lhs, rhs);
}



template<DataTagValue Value>
struct Tag {
  static const DataTagValue kValue = Value;
};

template<DataTagValue Value>
const DataTagValue Tag<Value>::kValue;

}  // detail

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_DATA_TYPE_VALUES_H_
