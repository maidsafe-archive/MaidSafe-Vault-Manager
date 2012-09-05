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
#include "maidsafe/private/return_codes.h"

// Note: These tests assume that there exists nonempty files publicly available on
// dash.maidsafe.net/~phil called e.g.
// lifestuff_(platform)(cpu_size)_(major_version).(minor_version).(patch_level)(extension),
// plus a file called file_list containing these filenames

namespace maidsafe {

namespace priv {

namespace process_management {

namespace test {

TEST(DownloadTest, BEH_Update_Successful) {
  DownloadManager download_manager("http", "dash.maidsafe.net", "~phil/tests/test_successful");
  std::vector<fs::path> updated_files;
  // NOTE: version file on server MUST be set to "1.01.02"
  download_manager.SetLatestLocalVersion("1.01.01");
  EXPECT_EQ(kSuccess, download_manager.Update(updated_files));
  EXPECT_FALSE(updated_files.empty());
  fs::path local_path(download_manager.GetLocalPath());
  LOG(kError) << "local_path: " << local_path;
  boost::system::error_code error;
  ASSERT_TRUE(fs::exists(local_path / "test_file1", error));
  ASSERT_EQ(boost::system::errc::success, error.value());
  error.clear();
  ASSERT_TRUE(fs::exists(local_path / "test_file2", error));
  ASSERT_EQ(boost::system::errc::success, error.value());
  error.clear();
  ASSERT_TRUE(fs::exists(local_path / "test_file3", error));
  ASSERT_EQ(boost::system::errc::success, error.value());
}

TEST(DownloadTest, BEH_Update_HasLatestVersion) {
  DownloadManager download_manager("http", "dash.maidsafe.net", "~phil/tests/test_has_latest");
  std::vector<fs::path> updated_files;
  // NOTE: version file on server MUST be set to "1.01.02"
  download_manager.SetLatestLocalVersion("1.01.02");
  EXPECT_EQ(kSuccess, download_manager.Update(updated_files));
  EXPECT_TRUE(updated_files.empty());
  fs::path local_path(download_manager.GetLocalPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file1", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  ASSERT_FALSE(fs::exists(local_path / "test_file2", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  ASSERT_FALSE(fs::exists(local_path / "test_file3", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

TEST(DownloadTest, BEH_Update_NoManifestFile) {
  DownloadManager download_manager("http", "dash.maidsafe.net", "~phil/tests/test_no_manifest");
  std::vector<fs::path> updated_files;
  // NOTE: version file on server MUST be set to "1.01.02"
  download_manager.SetLatestLocalVersion("1.01.01");
  EXPECT_EQ(kManifestFailure, download_manager.Update(updated_files));
  EXPECT_TRUE(updated_files.empty());
  fs::path local_path(download_manager.GetLocalPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file1", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  ASSERT_FALSE(fs::exists(local_path / "test_file2", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  ASSERT_FALSE(fs::exists(local_path / "test_file3", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

TEST(DownloadTest, BEH_Update_IncorrectManifestFile) {
  DownloadManager download_manager("http", "dash.maidsafe.net",
                                   "~phil/tests/test_incorrect_manifest");
  std::vector<fs::path> updated_files;
  // NOTE: version file on server MUST be set to "1.01.02"
  download_manager.SetLatestLocalVersion("1.01.01");
  EXPECT_EQ(kDownloadFailure, download_manager.Update(updated_files));
  fs::path local_path(download_manager.GetLocalPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file3", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

/*TEST(DownloadTest, BEH_Update_NoSignature) {
  DownloadManager download_manager("http", "dash.maidsafe.net", "~phil/tests/test_no_signature");
  std::vector<fs::path> updated_files;
  // NOTE: version file on server MUST be set to "1.01.02"
  download_manager.SetLatestLocalVersion("1.01.01");
  EXPECT_EQ(kDownloadFailure, download_manager.Update(updated_files));
  fs::path local_path(download_manager.GetLocalPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file3", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

TEST(DownloadTest, BEH_Update_InvalidSignature) {
  DownloadManager download_manager("http", "dash.maidsafe.net",
                                   "~phil/tests/test_incorrect_signature");
  std::vector<fs::path> updated_files;
  // NOTE: version file on server MUST be set to "1.01.02"
  download_manager.SetLatestLocalVersion("1.01.01");
  EXPECT_EQ(kDownloadFailure, download_manager.Update(updated_files));
  fs::path local_path(download_manager.GetLocalPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file3", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}*/

}  // namespace test

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
