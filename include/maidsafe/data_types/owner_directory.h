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

#ifndef MAIDSAFE_DATA_TYPES_OWNER_DIRECTORY_H_
#define MAIDSAFE_DATA_TYPES_OWNER_DIRECTORY_H_

#include <cstdint>

#include "maidsafe/common/types.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/data_types/data_type_values.h"


namespace maidsafe {

struct OwnerDirectoryTag {
  static const DataTagValue kEnumValue;
};

class OwnerDirectory {
 public:
  typedef TaggedValue<Identity, OwnerDirectoryTag> name_type;
  typedef TaggedValue<NonEmptyString, OwnerDirectoryTag> serialised_type;

  OwnerDirectory(const OwnerDirectory& other);
  OwnerDirectory& operator=(const OwnerDirectory& other);
  OwnerDirectory(OwnerDirectory&& other);
  OwnerDirectory& operator=(OwnerDirectory&& other);

  OwnerDirectory(const name_type& name, const NonEmptyString& data);
  OwnerDirectory(const name_type& name,
                 const NonEmptyString& data,
                 const asymm::PrivateKey& signing_key);
  OwnerDirectory(const name_type& name, const serialised_type& serialised_mutable_data);
  serialised_type Serialise() const;

  name_type name() const { return name_; }
  NonEmptyString data() const { return data_; }
  asymm::Signature signature() { return signature_; }
  static DataTagValue type_enum_value() { return OwnerDirectoryTag::kEnumValue; }

 private:
  name_type name_;
  NonEmptyString data_;
  asymm::Signature signature_;
};

template<>
struct is_short_term_cacheable<OwnerDirectory> : public std::true_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_OWNER_DIRECTORY_H_
