/***************************************************************************************************
 *  Copyright 2013 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#ifndef MAIDSAFE_DATA_TYPES_GROUP_DIRECTORY_H_
#define MAIDSAFE_DATA_TYPES_GROUP_DIRECTORY_H_

#include <cstdint>

#include "maidsafe/common/types.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/data_types/data_type_values.h"


namespace maidsafe {

struct GroupDirectoryTag {
  static const DataTagValue kEnumValue;
};

class GroupDirectory {
 public:
  typedef TaggedValue<Identity, GroupDirectoryTag> name_type;
  typedef TaggedValue<NonEmptyString, GroupDirectoryTag> serialised_type;

  GroupDirectory(const GroupDirectory& other);
  GroupDirectory& operator=(const GroupDirectory& other);
  GroupDirectory(GroupDirectory&& other);
  GroupDirectory& operator=(GroupDirectory&& other);

  GroupDirectory(const name_type& name, const NonEmptyString& data);
  GroupDirectory(const name_type& name,
                 const NonEmptyString& data,
                 const asymm::PrivateKey& signing_key);
  GroupDirectory(const name_type& name, const serialised_type& serialised_mutable_data);
  serialised_type Serialise() const;

  name_type name() const { return name_; }
  NonEmptyString data() const { return data_; }
  asymm::Signature signature() { return signature_; }
  static DataTagValue type_enum_value() { return GroupDirectoryTag::kEnumValue; }

 private:
  name_type name_;
  NonEmptyString data_;
  asymm::Signature signature_;
};

template<>
struct is_short_term_cacheable<GroupDirectory> : public std::true_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_GROUP_DIRECTORY_H_
