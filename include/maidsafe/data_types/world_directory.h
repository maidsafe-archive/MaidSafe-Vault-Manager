/*  Copyright 2013 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_DATA_TYPES_WORLD_DIRECTORY_H_
#define MAIDSAFE_DATA_TYPES_WORLD_DIRECTORY_H_

#include <cstdint>
#include <algorithm>

#include "maidsafe/common/types.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/data_types/data_type_values.h"


namespace maidsafe {

class WorldDirectory {
 public:
  typedef detail::Name<WorldDirectory> Name;
  typedef detail::Tag<DataTagValue::kWorldDirectoryValue> Tag;
  typedef TaggedValue<NonEmptyString, Tag> serialised_type;

  WorldDirectory(const WorldDirectory& other);
  WorldDirectory(WorldDirectory&& other);
  WorldDirectory& operator=(WorldDirectory other);

  WorldDirectory(Name name, NonEmptyString data);
  WorldDirectory(Name name, const serialised_type& serialised_mutable_data);
  serialised_type Serialise() const;

  Name name() const;
  NonEmptyString data() const;

  friend void swap(WorldDirectory& lhs, WorldDirectory& rhs);

 private:
  Name name_;
  NonEmptyString data_;
  asymm::Signature signature_;
};

template<>
struct is_short_term_cacheable<WorldDirectory> : public std::true_type {};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_WORLD_DIRECTORY_H_
