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

#ifndef MAIDSAFE_DATA_TYPES_IMMUTABLE_DATA_H_
#define MAIDSAFE_DATA_TYPES_IMMUTABLE_DATA_H_

#include "maidsafe/common/types.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/detail/data_type_values.h"


namespace maidsafe {

struct ImmutableDataTag {
  static const detail::DataTagValue kEnumValue = detail::DataTagValue::kImmutableDataValue;
};

class ImmutableData {
 public:
  typedef TaggedValue<Identity, ImmutableDataTag> name_type;
  typedef TaggedValue<NonEmptyString, ImmutableDataTag> serialised_type;

  ImmutableData(const ImmutableData& other);
  ImmutableData& operator=(const ImmutableData& other);
  ImmutableData(ImmutableData&& other);
  ImmutableData& operator=(ImmutableData&& other);

  ImmutableData(const name_type& name, const NonEmptyString& content);
  ImmutableData(const name_type& name, const serialised_type& serialised_immutable_data);
  serialised_type Serialise() const;

  name_type name() const { return name_; }
  NonEmptyString data() const { return data_; }
  static detail::DataTagValue type_enum_value() { return ImmutableDataTag::kEnumValue; }

 private:
  void Validate() const;
  name_type name_;
  NonEmptyString data_;
};

template<>
struct is_long_term_cacheable<ImmutableData> : public std::true_type {};

template<>
struct is_payable<ImmutableData> : public std::true_type {};

template<>
struct is_unique_on_network<ImmutableData> : public std::false_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_IMMUTABLE_DATA_H_
