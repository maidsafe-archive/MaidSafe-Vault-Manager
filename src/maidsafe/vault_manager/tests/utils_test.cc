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

#include "maidsafe/vault_manager/utils.h"

#include <string>

#include "maidsafe/common/test.h"

namespace maidsafe {

namespace vault_manager {

namespace test {

TEST(UtilsTest, DISABLED_BEH_WrapAndUnwrapMessage) { GTEST_FAIL() << "Needs test"; }

TEST(UtilsTest, BEH_GenerateVmidParameter) {
  EXPECT_EQ("0_0", GenerateVmidParameter(0, 0));
  EXPECT_EQ("0_65535", GenerateVmidParameter(0, 65535));
  EXPECT_EQ("1_65535", GenerateVmidParameter(1, 65535));
  EXPECT_EQ("1000_65535", GenerateVmidParameter(1000, 65535));
  EXPECT_EQ("1000_0", GenerateVmidParameter(1000, 0));
}

TEST(UtilsTest, DISABLED_BEH_ParseVmidParameter) { GTEST_FAIL() << "Needs test"; }

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe
