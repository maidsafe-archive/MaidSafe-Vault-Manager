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
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/detail/data_type_values.h"

namespace maidsafe {

struct ImmutableDataTag  {
  static const detail::DataTagValue kEnumValue = detail::DataTagValue::kImmutableDataValue;
};

class ImmutableData {
 public:
  typedef TaggedValue<Identity, ImmutableDataTag> name_type;
  typedef NonEmptyString serialised_type;

  ImmutableData(const name_type& name, const NonEmptyString& content);
  explicit ImmutableData(const NonEmptyString& serialised_data);
  NonEmptyString Serialise() const;
  NonEmptyString data() const;
  name_type name() const;
 private:
  void Validate();
  NonEmptyString data_;
  name_type name_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_IMMUTABLE_DATA_H_

