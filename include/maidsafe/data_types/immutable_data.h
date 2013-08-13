/* Copyright 2013 MaidSafe.net limited

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

#ifndef MAIDSAFE_DATA_TYPES_IMMUTABLE_DATA_H_
#define MAIDSAFE_DATA_TYPES_IMMUTABLE_DATA_H_

#include "maidsafe/common/types.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/data_types/data_type_values.h"


namespace maidsafe {

class ImmutableData {
 public:
  typedef detail::Name<ImmutableData> Name;
  typedef detail::Tag<DataTagValue::kImmutableDataValue> Tag;
  typedef TaggedValue<NonEmptyString, ImmutableData> serialised_type;

  ImmutableData(const ImmutableData& other);
  ImmutableData(ImmutableData&& other);
  ImmutableData& operator=(ImmutableData other);

  explicit ImmutableData(const NonEmptyString& content);
  ImmutableData(const Name& name, const serialised_type& serialised_immutable_data);
  ImmutableData(Name&& name, const serialised_type& serialised_immutable_data);
  serialised_type Serialise() const;

  Name name() const { return name_; }
  NonEmptyString data() const { return data_; }

  friend void swap(ImmutableData& lhs, ImmutableData& rhs);

 private:
  void Validate() const;
  Name name_;
  NonEmptyString data_;
};

template<>
struct is_long_term_cacheable<ImmutableData> : public std::true_type {};

template<>
struct is_unique_on_network<ImmutableData> : public std::false_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_IMMUTABLE_DATA_H_
