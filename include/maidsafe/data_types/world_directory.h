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

#ifndef MAIDSAFE_DATA_TYPES_WORLD_DIRECTORY_H_
#define MAIDSAFE_DATA_TYPES_WORLD_DIRECTORY_H_

#include <cstdint>

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

  WorldDirectory(const Name& name, const NonEmptyString& data);
  WorldDirectory(const Name& name,
                 const NonEmptyString& data,
                 const asymm::PrivateKey& signing_key);
  WorldDirectory(const Name& name, const serialised_type& serialised_mutable_data);
  serialised_type Serialise() const;

  Name name() const { return name_; }
  NonEmptyString data() const { return data_; }
  asymm::Signature signature() { return signature_; }

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
