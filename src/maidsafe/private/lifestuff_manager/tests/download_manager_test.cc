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

#include "maidsafe/private/lifestuff_manager/download_manager.h"
#include "maidsafe/private/lifestuff_manager/return_codes.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace test {

class DownloadManagerTest: public testing::Test {
 public:
  DownloadManagerTest() : download_manager_() {}

 protected:
  void InitialiseDownloadManager(const std::string& remote_location) {
    download_manager_.reset(new DownloadManager("http", "109.228.30.58", remote_location));
  }
  fs::path GetCurrentVersionDownloadPath() const {
    return download_manager_->local_path_ / download_manager_->latest_remote_version_;
  }
  void SetLatestLocalVersion(const std::string& version) {
    download_manager_->latest_local_version_ = version;
  }
  std::unique_ptr<DownloadManager> download_manager_;
};

TEST_F(DownloadManagerTest, BEH_Update_Successful) {
  InitialiseDownloadManager("/downloads/download_manager_tests/successful");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.001");
  EXPECT_EQ(kSuccess, download_manager_->Update(updated_files));
  EXPECT_FALSE(updated_files.empty());
  fs::path local_path(GetCurrentVersionDownloadPath());
  boost::system::error_code error;
  ASSERT_TRUE(fs::exists(local_path, error));
  ASSERT_EQ(boost::system::errc::success, error.value());
  error.clear();
  ASSERT_TRUE(fs::exists(local_path / "test_file1.gz", error));
  ASSERT_EQ(boost::system::errc::success, error.value());
  error.clear();
  ASSERT_TRUE(fs::exists(local_path / "test_file2.gz", error));
  ASSERT_EQ(boost::system::errc::success, error.value());
  error.clear();
  ASSERT_TRUE(fs::exists(local_path / "test_file3.gz", error));
  ASSERT_EQ(boost::system::errc::success, error.value());
}

TEST_F(DownloadManagerTest, BEH_Update_HasLatestVersion) {
  InitialiseDownloadManager("/downloads/download_manager_tests/has_latest");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.002");
  EXPECT_EQ(kNoVersionChange, download_manager_->Update(updated_files));
  EXPECT_TRUE(updated_files.empty());
  fs::path local_path(GetCurrentVersionDownloadPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file1.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  ASSERT_FALSE(fs::exists(local_path / "test_file2.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  ASSERT_FALSE(fs::exists(local_path / "test_file3.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

TEST_F(DownloadManagerTest, BEH_Update_NoManifestFile) {
  InitialiseDownloadManager("/downloads/download_manager_tests/no_manifest");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.001");
  EXPECT_EQ(kManifestFailure, download_manager_->Update(updated_files));
  EXPECT_TRUE(updated_files.empty());
  fs::path local_path(GetCurrentVersionDownloadPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file1.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  ASSERT_FALSE(fs::exists(local_path / "test_file2.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  ASSERT_FALSE(fs::exists(local_path / "test_file3.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

TEST_F(DownloadManagerTest, BEH_Update_IncorrectManifestFile) {
  InitialiseDownloadManager("/downloads/download_manager_tests/incorrect_manifest");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.001");
  EXPECT_EQ(kDownloadFailure, download_manager_->Update(updated_files));
  fs::path local_path(GetCurrentVersionDownloadPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file3.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

TEST_F(DownloadManagerTest, BEH_Update_NoSignature) {
  InitialiseDownloadManager("/downloads/download_manager_tests/no_signature");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.001");
  EXPECT_EQ(kDownloadFailure, download_manager_->Update(updated_files));
  fs::path local_path(GetCurrentVersionDownloadPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file3.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

TEST_F(DownloadManagerTest, BEH_Update_InvalidSignature) {
  InitialiseDownloadManager("/downloads/download_manager_tests/incorrect_signature");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.001");
  EXPECT_EQ(kDownloadFailure, download_manager_->Update(updated_files));
  fs::path local_path(GetCurrentVersionDownloadPath());
  boost::system::error_code error;
  ASSERT_FALSE(fs::exists(local_path / "test_file3.gz", error));
  ASSERT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

}  // namespace test

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe
