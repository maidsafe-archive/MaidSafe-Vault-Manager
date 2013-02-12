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

#include "maidsafe/data_types/immutable_data.h"
#include "maidsafe/data_types/owner_directory.h"
#include "maidsafe/data_types/group_directory.h"
#include "maidsafe/data_types/world_directory.h"


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

}  // namespace test

}  // namespace maidsafe
