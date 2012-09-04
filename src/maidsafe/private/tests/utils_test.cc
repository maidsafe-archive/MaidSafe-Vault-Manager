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

#include "maidsafe/private/process_management/utils.h"

#include <string>

#include "maidsafe/common/test.h"


namespace maidsafe {

namespace priv {

namespace process_management {

namespace detail {

namespace test {

TEST(UtilsTest, DISABLED_BEH_WrapAndUnwrapMessage) {
  FAIL() << "Needs test";
}

TEST(UtilsTest, BEH_VersionToString) {
  EXPECT_TRUE(VersionToString(-2).empty());
  EXPECT_TRUE(VersionToString(kInvalidVersion).empty());
  EXPECT_EQ("0.00.00", VersionToString(0));
  EXPECT_EQ("0.00.01", VersionToString(1));
  EXPECT_EQ("0.00.10", VersionToString(10));
  EXPECT_EQ("0.01.00", VersionToString(100));
  EXPECT_EQ("0.01.01", VersionToString(101));
  EXPECT_EQ("0.01.10", VersionToString(110));
  EXPECT_EQ("0.10.00", VersionToString(1000));
  EXPECT_EQ("0.10.01", VersionToString(1001));
  EXPECT_EQ("0.10.10", VersionToString(1010));
  EXPECT_EQ("1.00.00", VersionToString(10000));
  EXPECT_EQ("1.00.01", VersionToString(10001));
  EXPECT_EQ("1.00.10", VersionToString(10010));
  EXPECT_EQ("1.01.00", VersionToString(10100));
  EXPECT_EQ("1.01.01", VersionToString(10101));
  EXPECT_EQ("1.01.10", VersionToString(10110));
  EXPECT_EQ("1.10.00", VersionToString(11000));
  EXPECT_EQ("1.10.01", VersionToString(11001));
  EXPECT_EQ("1.10.10", VersionToString(11010));
  EXPECT_EQ("10.00.00", VersionToString(100000));
  EXPECT_EQ("10.00.01", VersionToString(100001));
  EXPECT_EQ("10.00.10", VersionToString(100010));
  EXPECT_EQ("10.01.00", VersionToString(100100));
  EXPECT_EQ("10.01.01", VersionToString(100101));
  EXPECT_EQ("10.01.10", VersionToString(100110));
  EXPECT_EQ("10.10.00", VersionToString(101000));
  EXPECT_EQ("10.10.01", VersionToString(101001));
  EXPECT_EQ("10.10.10", VersionToString(101010));
  std::string major_version, minor_version, patch_version;
  EXPECT_EQ("1.01.01", VersionToString(10101, &major_version, &minor_version, &patch_version));
  EXPECT_EQ("1", major_version);
  EXPECT_EQ("01", minor_version);
  EXPECT_EQ("01", patch_version);
  EXPECT_EQ("12.34.56", VersionToString(123456, &major_version, &minor_version, &patch_version));
  EXPECT_EQ("12", major_version);
  EXPECT_EQ("34", minor_version);
  EXPECT_EQ("56", patch_version);
}

TEST(UtilsTest, BEH_VersionToInt) {
  EXPECT_EQ(kInvalidVersion, VersionToInt(""));
  EXPECT_EQ(kInvalidVersion, VersionToInt("Rubbish"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("0.00.00.00"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("00.00"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("a.00.00"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("0.aa.00"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("0.00.aa"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("0.0.00"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("0.00.0"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("-1.00.00"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("0.-1.00"));
  EXPECT_EQ(kInvalidVersion, VersionToInt("0.00.-1"));
  EXPECT_EQ(0, VersionToInt("0.00.00"));
  EXPECT_EQ(1, VersionToInt("0.00.01"));
  EXPECT_EQ(10, VersionToInt("0.00.10"));
  EXPECT_EQ(100, VersionToInt("0.01.00"));
  EXPECT_EQ(101, VersionToInt("0.01.01"));
  EXPECT_EQ(110, VersionToInt("0.01.10"));
  EXPECT_EQ(1000, VersionToInt("0.10.00"));
  EXPECT_EQ(1001, VersionToInt("0.10.01"));
  EXPECT_EQ(1010, VersionToInt("0.10.10"));
  EXPECT_EQ(10000, VersionToInt("1.00.00"));
  EXPECT_EQ(10001, VersionToInt("1.00.01"));
  EXPECT_EQ(10010, VersionToInt("1.00.10"));
  EXPECT_EQ(10100, VersionToInt("1.01.00"));
  EXPECT_EQ(10101, VersionToInt("1.01.01"));
  EXPECT_EQ(10110, VersionToInt("1.01.10"));
  EXPECT_EQ(11000, VersionToInt("1.10.00"));
  EXPECT_EQ(11001, VersionToInt("1.10.01"));
  EXPECT_EQ(11010, VersionToInt("1.10.10"));
  EXPECT_EQ(100000, VersionToInt("10.00.00"));
  EXPECT_EQ(100001, VersionToInt("10.00.01"));
  EXPECT_EQ(100010, VersionToInt("10.00.10"));
  EXPECT_EQ(100100, VersionToInt("10.01.00"));
  EXPECT_EQ(100101, VersionToInt("10.01.01"));
  EXPECT_EQ(100110, VersionToInt("10.01.10"));
  EXPECT_EQ(101000, VersionToInt("10.10.00"));
  EXPECT_EQ(101001, VersionToInt("10.10.01"));
  EXPECT_EQ(101010, VersionToInt("10.10.10"));
}

TEST(UtilsTest, DISABLED_BEH_GenerateFileName) {
  FAIL() << "Needs test";
}

TEST(UtilsTest, DISABLED_BEH_TokeniseFileName) {
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

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
