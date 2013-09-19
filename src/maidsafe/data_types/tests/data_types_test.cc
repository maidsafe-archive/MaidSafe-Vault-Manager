/*  Copyright 2012 MaidSafe.net limited

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
