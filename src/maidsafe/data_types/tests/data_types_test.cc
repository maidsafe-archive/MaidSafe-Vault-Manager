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

#include <string>

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/data_types/data_name_variant.h"


namespace maidsafe {

namespace test {

TEST(DataTypesTest, BEH_ConstructType) {
  // EXPECT_NO_THROW(DataHolder data_holder);
  static_assert(is_short_term_cacheable<OwnerDirectory>::value, "");
  static_assert(is_short_term_cacheable<GroupDirectory>::value, "");
  static_assert(is_short_term_cacheable<WorldDirectory>::value, "");
  static_assert(!is_long_term_cacheable<OwnerDirectory>::value, "");
  static_assert(!is_long_term_cacheable<GroupDirectory>::value, "");
  static_assert(!is_long_term_cacheable<WorldDirectory>::value, "");
  static_assert(!is_short_term_cacheable<ImmutableData>::value, "");
  static_assert(is_long_term_cacheable<ImmutableData>::value, "");
}

TEST(DataTypesTest, BEH_RetrieveType) {
  Identity id(RandomString(64));

  static_assert(std::is_same<passport::PublicAnmid,
                             passport::PublicAnmid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::PublicAnsmid,
                             passport::PublicAnsmid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::PublicAntmid,
                             passport::PublicAntmid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::PublicAnmaid,
                             passport::PublicAnmaid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::PublicMaid,
                             passport::PublicMaid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::PublicPmid,
                             passport::PublicPmid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::Mid, passport::Mid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::Smid, passport::Smid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::Tmid, passport::Tmid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::PublicAnmpid,
                             passport::PublicAnmpid::Name::data_type>::value, "");
  static_assert(std::is_same<passport::PublicMpid,
                             passport::PublicMpid::Name::data_type>::value, "");
  static_assert(std::is_same<ImmutableData, ImmutableData::Name::data_type>::value, "");
  static_assert(std::is_same<OwnerDirectory, OwnerDirectory::Name::data_type>::value, "");
  static_assert(std::is_same<GroupDirectory, GroupDirectory::Name::data_type>::value, "");
  static_assert(std::is_same<WorldDirectory, WorldDirectory::Name::data_type>::value, "");
}

}  // namespace test

}  // namespace maidsafe
