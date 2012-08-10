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
#include "maidsafe/private/download_manager.h"
/*Note: These tests assume that there exists nonempty files publicly available on
 * dash.maidsafe.net/~phil called garbage, lifestuff_(platform)_(cpu_size)_(version)_(patch_level),
 * plus a file called file_list containing these filenames
*/

namespace maidsafe {

namespace priv {

namespace test {

class DownloadTest : public testing::Test {
 public:
  DownloadTest() : platform_(), extension_(), cpu_size_() {
    cpu_size_ = boost::lexical_cast<std::string>(CpuSize());
    #if defined MAIDSAFE_WIN32
      platform_ = "win" + cpu_size_;
      extension_ = ".exe";
    #elif defined MAIDSAFE_APPLE
      platform_ = "osx" + cpu_size_;
    #else
      platform_ = "linux" + cpu_size_;
    #endif
  }
  ~DownloadTest() {}
 protected:
  std::string platform_;
  std::string extension_;
  std::string cpu_size_;
};

TEST_F(DownloadTest, BEH_FindLatestFile) {
  std::shared_ptr<boost::filesystem::path> test_dir_
      (maidsafe::test::CreateTestPath("MaidSafe_TestDownloadManager"));

  // Test case for non-existent file
  DownloadManager manager("dash.maidsafe.net", "~phil", "dummy", "dummyplatform", "1",
                                    "0", "0");
  EXPECT_FALSE(manager.FindLatestFile());

  // Test case for file that we already have the latest version/patch level of the file
  manager.SetNameToDownload("lifestuff");
  manager.SetPlatformToUpdate(platform_);
  manager.SetCurrentMajorVersionToUpdate("1");
  manager.SetCurrentMinorVersionToUpdate("1");
  manager.SetCurrentPatchLevelToUpdate("3");
  EXPECT_FALSE(manager.FindLatestFile());
  EXPECT_EQ("", manager.file_to_download() + extension_);

  // Test case for file that is a later version / patch level than the one requested
  manager.SetCurrentPatchLevelToUpdate("2");
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestuff_" + platform_ + "_1.1.3" + extension_,
            manager.file_to_download() + extension_);

  // Test case where the must choose the latest of two later versions of the file
  manager.ClearFileToDownload();
  manager.SetCurrentPatchLevelToUpdate("1");
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestuff_" + platform_ + "_1.1.3" + extension_,
            manager.file_to_download() + extension_);
}

TEST_F(DownloadTest, BEH_UpdateFile) {
  std::shared_ptr<boost::filesystem::path> test_dir_
      (maidsafe::test::CreateTestPath("MaidSafe_TestDownloadManager"));

  DownloadManager manager("dash.maidsafe.net", "~phil", "lifestuff", platform_, "1", "1", "1");
  
  // Current file should not be updated without finding the latest file first
  EXPECT_FALSE(manager.UpdateCurrentFile(*test_dir_));
  
  // Successful test case
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestuff_" + platform_ + "_1.1.3" + extension_,
            manager.file_to_download() + extension_);
  EXPECT_TRUE(manager.UpdateCurrentFile(*test_dir_));
  EXPECT_TRUE(boost::filesystem::exists(*test_dir_
              / boost::lexical_cast<std::string>("lifestuff_" + platform_ + "_1.1.3" + extension_)));
  EXPECT_FALSE(boost::filesystem::is_empty(*test_dir_
              / boost::lexical_cast<std::string>("lifestuff_" + platform_ + "_1.1.3" + extension_)));
  std::string content;
  ReadFile(*test_dir_ / "lifestuff_" / platform_ / "_1.1.3" / extension_, &content);
  LOG(kInfo) << content;
}

TEST_F(DownloadTest, BEH_UpdateFileNewerVersion) {
  std::shared_ptr<boost::filesystem::path> test_dir_
      (maidsafe::test::CreateTestPath("MaidSafe_TestDownloadManager"));

  DownloadManager manager("dash.maidsafe.net", "~phil", "lifestufflocal", platform_, "4", "4", "6");
  // Download a version of lifestuff
  manager.SetFileToDownload("lifestufflocal_" + platform_ + "_4.4.6" + extension_);
  EXPECT_TRUE(manager.UpdateCurrentFile(*test_dir_));

  // Try to find the latest version which has bigger version than the current one but has smaller
  // patch level
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestufflocal_" + platform_ + "_5.5.4" + extension_, manager.file_to_download()
            + extension_);
  EXPECT_TRUE(manager.UpdateCurrentFile(*test_dir_));
  EXPECT_TRUE(boost::filesystem::exists(*test_dir_
              / boost::lexical_cast<std::string>("lifestufflocal_" + platform_ + "_5.5.4" + extension_)));
  EXPECT_FALSE(boost::filesystem::is_empty(*test_dir_
              / boost::lexical_cast<std::string>("lifestufflocal_" + platform_ + "_5.5.4" + extension_)));
}

TEST_F(DownloadTest, BEH_VerificationOfFiles) {
  boost::filesystem::path current_path(boost::filesystem::current_path());

  DownloadManager manager("dash.maidsafe.net", "~phil", "lifestufflocal", platform_, "1", "1", "1");

  // Find the latest file and donwload it together with its signature file
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestufflocal_" + platform_ + "_5.5.4" + extension_, manager.file_to_download()
            + extension_);

  std::string signature_file = "lifestufflocal_" + platform_ + "_5.5.4" + extension_ + ".sig";
  manager.SetFileToDownload(signature_file);
  EXPECT_TRUE(manager.UpdateCurrentFile(current_path));
  EXPECT_TRUE(boost::filesystem::exists(current_path / signature_file));
  EXPECT_FALSE(boost::filesystem::is_empty(current_path / signature_file));

  std::string file_to_download = "lifestufflocal_" + platform_ + "_5.5.4" + extension_;
  manager.SetFileToDownload(file_to_download);
  EXPECT_TRUE(manager.UpdateCurrentFile(current_path));
  EXPECT_TRUE(boost::filesystem::exists(current_path / file_to_download));
  EXPECT_FALSE(boost::filesystem::is_empty(current_path / file_to_download));

  EXPECT_TRUE(manager.VerifySignature());

  boost::filesystem::remove(current_path / signature_file);
  boost::filesystem::remove(current_path / file_to_download);
}

TEST_F(DownloadTest, BEH_VerificationFail) {
  boost::filesystem::path current_path(boost::filesystem::current_path());

  DownloadManager manager("dash.maidsafe.net", "~phil", "lifestufflocal", platform_, "1", "1", "1");

  std::string signature_file = "lifestufflocal_" + platform_ + "_5.5.3" + extension_ + ".sig";
  manager.SetFileToDownload(signature_file);
  EXPECT_TRUE(manager.UpdateCurrentFile(current_path));
  EXPECT_TRUE(boost::filesystem::exists(current_path / signature_file));
  EXPECT_FALSE(boost::filesystem::is_empty(current_path / signature_file));

  std::string file_to_download = "lifestufflocal_" + platform_ + "_5.5.3" + extension_;
  manager.SetFileToDownload(file_to_download);
  EXPECT_TRUE(manager.UpdateCurrentFile(current_path));
  EXPECT_TRUE(boost::filesystem::exists(current_path / file_to_download));
  EXPECT_FALSE(boost::filesystem::is_empty(current_path / file_to_download));

  EXPECT_FALSE(manager.VerifySignature());

  boost::filesystem::remove(current_path / signature_file);
  boost::filesystem::remove(current_path / file_to_download);
}

}  // namespace test

}  // namespace priv

}  // namespace maidsafe

int main(int argc, char **argv) {
  maidsafe::log::FilterMap filter;
  filter["*"] = maidsafe::log::kInfo;
  return ExecuteMain(argc, argv, filter);
}
