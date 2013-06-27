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



#include "maidsafe/lifestuff_manager/utils.h"

#include <string>

#include "maidsafe/common/test.h"


namespace maidsafe {

namespace lifestuff_manager {

namespace detail {

namespace test {

TEST(UtilsTest, DISABLED_BEH_WrapAndUnwrapMessage) {
  FAIL() << "Needs test";
}

TEST(UtilsTest, BEH_GenerateVmidParameter) {
  EXPECT_EQ("0_0", GenerateVmidParameter(0, 0));
  EXPECT_EQ("0_65535", GenerateVmidParameter(0, 65535));
  EXPECT_EQ("1_65535", GenerateVmidParameter(1, 65535));
  EXPECT_EQ("1000_65535", GenerateVmidParameter(1000, 65535));
  EXPECT_EQ("1000_0", GenerateVmidParameter(1000, 0));
}

TEST(UtilsTest, DISABLED_BEH_ParseVmidParameter) {
  FAIL() << "Needs test";
}

}  // namespace test

}  // namespace detail

}  // namespace lifestuff_manager

}  // namespace maidsafe
