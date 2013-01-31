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

#ifndef MAIDSAFE_DATA_TYPES_WORLD_DIRECTORY_H_
#define MAIDSAFE_DATA_TYPES_WORLD_DIRECTORY_H_

#include <cstdint>

#include "maidsafe/common/types.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/data_types/data_type_values.h"


namespace maidsafe {

struct WorldDirectoryTag {
  static const DataTagValue kEnumValue;
};

class WorldDirectory {
 public:
  typedef TaggedValue<Identity, WorldDirectoryTag> name_type;
  typedef TaggedValue<NonEmptyString, WorldDirectoryTag> serialised_type;

  WorldDirectory(const WorldDirectory& other);
  WorldDirectory& operator=(const WorldDirectory& other);
  WorldDirectory(WorldDirectory&& other);
  WorldDirectory& operator=(WorldDirectory&& other);

  WorldDirectory(const name_type& name, const NonEmptyString& data);
  WorldDirectory(const name_type& name,
                 const NonEmptyString& data,
                 const asymm::PrivateKey& signing_key);
  WorldDirectory(const name_type& name, const serialised_type& serialised_mutable_data);
  serialised_type Serialise() const;

  name_type name() const { return name_; }
  NonEmptyString data() const { return data_; }
  asymm::Signature signature() { return signature_; }
  static DataTagValue type_enum_value() { return WorldDirectoryTag::kEnumValue; }

 private:
  name_type name_;
  NonEmptyString data_;
  asymm::Signature signature_;
};

template<>
struct is_short_term_cacheable<WorldDirectory> : public std::true_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_WORLD_DIRECTORY_H_
