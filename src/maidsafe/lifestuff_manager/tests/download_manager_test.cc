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



#include <thread>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

#include "maidsafe/lifestuff_manager/download_manager.h"
#include "maidsafe/lifestuff_manager/return_codes.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff_manager {

namespace test {

class DownloadManagerTest: public testing::Test {
 public:
  DownloadManagerTest() : download_manager_() {}

 protected:
  void InitialiseDownloadManager(const std::string& remote_location) {
    download_manager_.reset(new DownloadManager(remote_location));
  }
  fs::path GetCurrentVersionDownloadPath() const {
    return download_manager_->local_path_ / download_manager_->latest_remote_version_;
  }
  void SetLatestLocalVersion(const std::string& version) {
    download_manager_->latest_local_version_ = version;
  }
  std::unique_ptr<DownloadManager> download_manager_;
};

TEST_F(DownloadManagerTest, BEH_UpdateSuccessful) {
  InitialiseDownloadManager("/downloads/download_manager_tests/successful");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.001");
  EXPECT_EQ(kSuccess, download_manager_->Update(updated_files));

  EXPECT_EQ(3U, updated_files.size());
  fs::path local_path(GetCurrentVersionDownloadPath());
  EXPECT_TRUE(std::find(updated_files.begin(), updated_files.end(),
                        (local_path / "test_file1.gz").string()) != updated_files.end());
  EXPECT_TRUE(std::find(updated_files.begin(), updated_files.end(),
                        (local_path / "test_file2.gz").string()) != updated_files.end());
  EXPECT_TRUE(std::find(updated_files.begin(), updated_files.end(),
                        (local_path / "test_file3.gz").string()) != updated_files.end());

  boost::system::error_code error;
  EXPECT_TRUE(fs::exists(local_path, error));
  EXPECT_EQ(boost::system::errc::success, error.value());

  for (auto updated_file : updated_files) {
    error.clear();
    EXPECT_TRUE(fs::exists(updated_file, error));
    EXPECT_EQ(boost::system::errc::success, error.value());
  }
}

TEST_F(DownloadManagerTest, BEH_UpdateHasLatestVersion) {
  InitialiseDownloadManager("/downloads/download_manager_tests/has_latest");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.002");
  EXPECT_EQ(kNoVersionChange, download_manager_->Update(updated_files));
  EXPECT_TRUE(updated_files.empty());
  boost::system::error_code error;
  EXPECT_FALSE(fs::exists(GetCurrentVersionDownloadPath(), error));
  EXPECT_EQ(boost::system::errc::no_such_file_or_directory, error.value()) << error.message();
}

TEST_F(DownloadManagerTest, BEH_UpdateNoManifestFile) {
  InitialiseDownloadManager("/downloads/download_manager_tests/no_manifest");
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.001");
  EXPECT_EQ(kManifestFailure, download_manager_->Update(updated_files));
  EXPECT_TRUE(updated_files.empty());
  fs::path local_path(GetCurrentVersionDownloadPath());
  boost::system::error_code error;
  EXPECT_FALSE(fs::exists(local_path / "test_file1.gz", error));
  EXPECT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  EXPECT_FALSE(fs::exists(local_path / "test_file2.gz", error));
  EXPECT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
  error.clear();
  EXPECT_FALSE(fs::exists(local_path / "test_file3.gz", error));
  EXPECT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

class DownloadManagerCommonTest : public DownloadManagerTest,
                                  public ::testing::WithParamInterface<std::string> {};  // NOLINT (Fraser)

TEST_P(DownloadManagerCommonTest, BEH_UpdateThirdFileFail) {
  InitialiseDownloadManager("/downloads/download_manager_tests/" + GetParam());
  std::vector<fs::path> updated_files;
  SetLatestLocalVersion("1.1.001");
  EXPECT_EQ(kSuccess, download_manager_->Update(updated_files));

  EXPECT_EQ(2U, updated_files.size());
  fs::path local_path(GetCurrentVersionDownloadPath());
  EXPECT_TRUE(std::find(updated_files.begin(), updated_files.end(),
                        (local_path / "test_file1.gz").string()) != updated_files.end());
  EXPECT_TRUE(std::find(updated_files.begin(), updated_files.end(),
                        (local_path / "test_file2.gz").string()) != updated_files.end());
  EXPECT_FALSE(std::find(updated_files.begin(), updated_files.end(),
                         (local_path / "test_file3.gz").string()) != updated_files.end());

  boost::system::error_code error;
  EXPECT_TRUE(fs::exists(local_path, error));
  EXPECT_EQ(boost::system::errc::success, error.value());
  error.clear();
  EXPECT_TRUE(fs::exists(local_path / "test_file1.gz", error));
  EXPECT_EQ(boost::system::errc::success, error.value());
  error.clear();
  EXPECT_TRUE(fs::exists(local_path / "test_file2.gz", error));
  EXPECT_EQ(boost::system::errc::success, error.value());
  error.clear();
  EXPECT_FALSE(fs::exists(local_path / "test_file3.gz", error));
  EXPECT_EQ(boost::system::errc::no_such_file_or_directory, error.value());
}

INSTANTIATE_TEST_CASE_P(AllFail,
                        DownloadManagerCommonTest,
                        testing::Values("incorrect_manifest",
                                        "no_signature",
                                        "incorrect_signature"));

}  // namespace test

}  // namespace lifestuff_manager

}  // namespace maidsafe
