/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/


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

  ASSERT_FALSE(is_maidsafe_data<static_cast<DataTagValue>(-1)>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kAnmidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kAnsmidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kAntmidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kAnmaidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kPmidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kMidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kSmidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kTmidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kAnmpidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kMpidValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kImmutableDataValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kOwnerDirectoryValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kGroupDirectoryValue>::value);
  ASSERT_TRUE(is_maidsafe_data<DataTagValue::kWorldDirectoryValue>::value);

  static_assert(!is_maidsafe_data<static_cast<DataTagValue>(-1)>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kAnmidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAnmidValue>::data_type,
                             passport::PublicAnmid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAnmidValue>::name_type,
                             passport::PublicAnmid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kAnsmidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAnsmidValue>::data_type,
                             passport::PublicAnsmid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAnsmidValue>::name_type,
                             passport::PublicAnsmid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kAntmidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAntmidValue>::data_type,
                             passport::PublicAntmid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAntmidValue>::name_type,
                             passport::PublicAntmid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kAnmaidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAnmaidValue>::data_type,
                             passport::PublicAnmaid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAnmaidValue>::name_type,
                             passport::PublicAnmaid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kMaidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kMaidValue>::data_type,
                             passport::PublicMaid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kMaidValue>::name_type,
                             passport::PublicMaid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kPmidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kPmidValue>::data_type,
                             passport::PublicPmid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kPmidValue>::name_type,
                             passport::PublicPmid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kMidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kMidValue>::data_type,
                             passport::Mid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kMidValue>::name_type,
                             passport::Mid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kSmidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kSmidValue>::data_type,
                             passport::Smid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kSmidValue>::name_type,
                             passport::Smid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kTmidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kTmidValue>::data_type,
                             passport::Tmid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kTmidValue>::name_type,
                             passport::Tmid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kAnmpidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAnmpidValue>::data_type,
                             passport::PublicAnmpid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kAnmpidValue>::name_type,
                             passport::PublicAnmpid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kMpidValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kMpidValue>::data_type,
                             passport::PublicMpid>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kMpidValue>::name_type,
                             passport::PublicMpid::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kImmutableDataValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kImmutableDataValue>::data_type,
                             ImmutableData>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kImmutableDataValue>::name_type,
                             ImmutableData::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kOwnerDirectoryValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kOwnerDirectoryValue>::data_type,
                             OwnerDirectory>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kOwnerDirectoryValue>::name_type,
                             OwnerDirectory::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kGroupDirectoryValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kGroupDirectoryValue>::data_type,
                             GroupDirectory>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kGroupDirectoryValue>::name_type,
                             GroupDirectory::name_type>::value, "");

  static_assert(is_maidsafe_data<DataTagValue::kWorldDirectoryValue>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kWorldDirectoryValue>::data_type,
                             WorldDirectory>::value, "");
  static_assert(std::is_same<is_maidsafe_data<DataTagValue::kWorldDirectoryValue>::name_type,
                             WorldDirectory::name_type>::value, "");

  auto anmid_name(GetName<DataTagValue::kAnmidValue>(id));
  static_assert(std::is_same<decltype(anmid_name), passport::PublicAnmid::name_type>::value, "");
  auto ansmid_name(GetName<DataTagValue::kAnsmidValue>(id));
  static_assert(std::is_same<decltype(ansmid_name), passport::PublicAnsmid::name_type>::value, "");
  auto antmid_name(GetName<DataTagValue::kAntmidValue>(id));
  static_assert(std::is_same<decltype(antmid_name), passport::PublicAntmid::name_type>::value, "");
  auto anmaid_name(GetName<DataTagValue::kAnmaidValue>(id));
  static_assert(std::is_same<decltype(anmaid_name), passport::PublicAnmaid::name_type>::value, "");
  auto maid_name(GetName<DataTagValue::kMaidValue>(id));
  static_assert(std::is_same<decltype(maid_name), passport::PublicMaid::name_type>::value, "");
  auto pmid_name(GetName<DataTagValue::kPmidValue>(id));
  static_assert(std::is_same<decltype(pmid_name), passport::PublicPmid::name_type>::value, "");
  auto mid_name(GetName<DataTagValue::kMidValue>(id));
  static_assert(std::is_same<decltype(mid_name), passport::Mid::name_type>::value, "");
  auto smid_name(GetName<DataTagValue::kSmidValue>(id));
  static_assert(std::is_same<decltype(smid_name), passport::Smid::name_type>::value, "");
  auto tmid_name(GetName<DataTagValue::kTmidValue>(id));
  static_assert(std::is_same<decltype(tmid_name), passport::Tmid::name_type>::value, "");
  auto anmpid_name(GetName<DataTagValue::kAnmpidValue>(id));
  static_assert(std::is_same<decltype(anmpid_name), passport::PublicAnmpid::name_type>::value, "");
  auto mpid_name(GetName<DataTagValue::kMpidValue>(id));
  static_assert(std::is_same<decltype(mpid_name), passport::PublicMpid::name_type>::value, "");
  auto immutable_data_name(GetName<DataTagValue::kImmutableDataValue>(id));
  static_assert(std::is_same<decltype(immutable_data_name), ImmutableData::name_type>::value, "");
  auto owner_directory_name(GetName<DataTagValue::kOwnerDirectoryValue>(id));
  static_assert(std::is_same<decltype(owner_directory_name), OwnerDirectory::name_type>::value, "");
  auto group_directory_name(GetName<DataTagValue::kGroupDirectoryValue>(id));
  static_assert(std::is_same<decltype(group_directory_name), GroupDirectory::name_type>::value, "");
  auto world_directory_name(GetName<DataTagValue::kWorldDirectoryValue>(id));
  static_assert(std::is_same<decltype(world_directory_name), WorldDirectory::name_type>::value, "");
}

}  // namespace test

}  // namespace maidsafe
