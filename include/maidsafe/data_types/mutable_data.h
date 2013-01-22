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

#ifndef MAIDSAFE_DATA_TYPES_MUTABLE_DATA_H_
#define MAIDSAFE_DATA_TYPES_MUTABLE_DATA_H_

#include <cstdint>

#include "maidsafe/common/types.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/detail/data_type_values.h"


namespace maidsafe {

struct MutableDataTag {
  static const detail::DataTagValue kEnumValue = detail::DataTagValue::kMutableDataValue;
};

class MutableData {
 public:
  typedef TaggedValue<Identity, MutableDataTag> name_type;
  typedef TaggedValue<NonEmptyString, MutableDataTag> serialised_type;

  MutableData(const MutableData& other);
  MutableData& operator=(const MutableData& other);
  MutableData(MutableData&& other);
  MutableData& operator=(MutableData&& other);

  explicit MutableData(const NonEmptyString& data);
  MutableData(const NonEmptyString& data, const asymm::PrivateKey& signing_key);
  MutableData(const name_type& name, const serialised_type& serialised_mutable_data);
  serialised_type Serialise() const;

  name_type name() const { return name_; }
  NonEmptyString data() const { return data_; }
  asymm::Signature signature() { return signature_; }
  static detail::DataTagValue type_enum_value() { return MutableDataTag::kEnumValue; }

 private:
  void Validate(const serialised_type& serialised_mutable_data) const;
  name_type CalculateName();

  name_type name_;
  NonEmptyString data_;
  asymm::Signature signature_;
};

template<>
struct is_short_term_cacheable<MutableData> : public std::true_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_MUTABLE_DATA_H_

