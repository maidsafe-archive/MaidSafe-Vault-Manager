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

#include <thread>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"
#include "maidsafe/private/process_management/download_manager.h"

// Note: These tests assume that there exists nonempty files publicly available on
// dash.maidsafe.net/~phil called e.g.
// lifestuff_(platform)(cpu_size)_(major_version).(minor_version).(patch_level)(extension),
// plus a file called file_list containing these filenames

namespace maidsafe {

namespace priv {

namespace process_management {

namespace test {

TEST(DownloadTest, BEH_UpdateAndVerify) {
  maidsafe::test::TestPath test_path(
      maidsafe::test::CreateTestPath("MaidSafe_Test_DownloadManager"));
  DownloadManager download_manager("http", "dash.maidsafe.net", "~phil");

  // Test case for non-existent file
  std::string newest_version(download_manager.UpdateAndVerify("non-existent", *test_path));
  EXPECT_TRUE(newest_version.empty());

  // Test case for file with malformed name
  newest_version = download_manager.UpdateAndVerify("lifestuff_osx64_1.1.02", *test_path);
  EXPECT_TRUE(newest_version.empty());

  // Test case for unsigned file
  newest_version = download_manager.UpdateAndVerify("lifestufflocaltest_win64_4.04.06", *test_path);
  EXPECT_TRUE(newest_version.empty());

  // Test case for file with invalid signature
  newest_version =
      download_manager.UpdateAndVerify("lifestuff-bad-sig_win64_1.01.02.exe", *test_path);
  EXPECT_TRUE(newest_version.empty());

  // Test case for files where we already have the newest version
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_linux32_5.05.04", *test_path);
  EXPECT_TRUE(newest_version.empty());
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_linux64_5.05.04", *test_path);
  EXPECT_TRUE(newest_version.empty());
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_osx32_5.05.04", *test_path);
  EXPECT_TRUE(newest_version.empty());
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_osx64_5.05.04", *test_path);
  EXPECT_TRUE(newest_version.empty());
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_win32_5.05.04.exe", *test_path);
  EXPECT_TRUE(newest_version.empty());
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_win64_5.05.04.exe", *test_path);
  EXPECT_TRUE(newest_version.empty());

  // Test case for files where we don't have the newest version
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_linux32_5.05.03", *test_path);
  EXPECT_EQ("lifestufflocal_linux32_5.05.04", newest_version);
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_linux64_5.04.04", *test_path);
  EXPECT_EQ("lifestufflocal_linux64_5.05.04", newest_version);
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_osx32_4.05.03", *test_path);
  EXPECT_EQ("lifestufflocal_osx32_5.05.04", newest_version);
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_osx64_5.04.99", *test_path);
  EXPECT_EQ("lifestufflocal_osx64_5.05.04", newest_version);
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_win32_4.99.04.exe", *test_path);
  EXPECT_EQ("lifestufflocal_win32_5.05.04.exe", newest_version);
  newest_version = download_manager.UpdateAndVerify("lifestufflocal_win64_4.99.99.exe", *test_path);
  EXPECT_EQ("lifestufflocal_win64_5.05.04.exe", newest_version);
}

}  // namespace test

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
