/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <thread>
#include <string>
#include <vector>

#include "boost/filesystem.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"
#include "maidsafe/private/download_manager.h"
/*Note: These tests assume that there exists nonempty files publicly available on
 * dash.maidsafe.net/~phil called garbage, lifestuff_linux_32_1_1, lifestuff_linux_32_1_2 and
 * lifestuff_linux_32_1_3, plus a file called file_list containing these filenames
*/
namespace maidsafe {

namespace test {

TEST(DownloadManagerTest, BEH_FindLatestFile) {
  std::shared_ptr<boost::filesystem::path> test_dir_
      (maidsafe::test::CreateTestPath("TestDownloadManager"));

  // Test case for non-existent file
  maidsafe::DownloadManager manager("dash.maidsafe.net", "~phil", "dummy", "dummyplatform", "1",
                                    "0", "0");
  EXPECT_FALSE(manager.FindLatestFile());

  // Test case for file that we already have the latest version/patch level of the file
  manager.SetNameToDownload("lifestuff");
  manager.SetPlatformToUpdate("linux");
  manager.SetCpuSizeToUpdate("32");
  manager.SetCurrentVersionToUpdate("1");
  manager.SetCurrentPatchLevelToUpdate("3");
  EXPECT_FALSE(manager.FindLatestFile());
  EXPECT_EQ("", manager.file_to_download());

  // Test case for file that is a later version / patch level than the one requested
  manager.SetCurrentPatchLevelToUpdate("2");
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestuff_linux_32_1_3", manager.file_to_download());

  // Test case where the must choose the latest of two later versions of the file
  manager.ClearFileToDownload();
  manager.SetCurrentPatchLevelToUpdate("1");
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestuff_linux_32_1_3", manager.file_to_download());
}

TEST(DownloadManagerTest, BEH_UpdateFile) {
  std::shared_ptr<boost::filesystem::path> test_dir_
      (maidsafe::test::CreateTestPath("TestDownloadManager"));
  maidsafe::DownloadManager manager("dash.maidsafe.net", "~phil", "lifestuff", "linux", "32", "1",
                                    "1");
  // Current file should not be updated without finding the latest file first
  EXPECT_FALSE(manager.UpdateCurrentFile(*test_dir_));
  // Successful test case
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestuff_linux_32_1_3", manager.file_to_download());
  EXPECT_TRUE(manager.UpdateCurrentFile(*test_dir_));
  EXPECT_TRUE(boost::filesystem::exists(*test_dir_ / "lifestuff_linux_32_1_3"));
  EXPECT_FALSE(boost::filesystem::is_empty(*test_dir_ / "lifestuff_linux_32_1_3"));
  std::string content;
  ReadFile(*test_dir_ / "lifestuff_linux_32_1_3", &content);
  LOG(kInfo) << content;
}

TEST(DownloadManagerTest, BEH_UpdateFileNewerVersion_SmallerPatchLevel) {
  std::shared_ptr<boost::filesystem::path> test_dir_
      (maidsafe::test::CreateTestPath("TestDownloadManager"));
  std::string extension = "";

  #ifdef _WINDOWS
    extension = ".exe";
  #endif

  maidsafe::DownloadManager manager("dash.maidsafe.net", "~phil", "lifestufflocal", "linux",
                                    "32", "4", "6");
  // Download a version of lifestuff
  manager.SetFileToDownload("lifestufflocal_linux_32_4_6" + extension);
  EXPECT_TRUE(manager.UpdateCurrentFile(*test_dir_));

  // Try to find the latest version which has bigger version than the current one but has smaller
  // patch level
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestufflocal_linux_32_5_4" + extension, manager.file_to_download() + extension);
  EXPECT_TRUE(manager.UpdateCurrentFile(*test_dir_));
  EXPECT_TRUE(boost::filesystem::exists(*test_dir_ / "lifestufflocal_linux_32_5_4"));
  EXPECT_FALSE(boost::filesystem::is_empty(*test_dir_ / "lifestufflocal_linux_32_5_4"));
}

TEST(DownloadManagerTest, BEH_VerificationOfFiles) {
  boost::filesystem::path current_path(boost::filesystem::current_path());
  std::string extension = "";
  #ifdef _WINDOWS
    extension = ".exe";
  #endif
  maidsafe::DownloadManager manager("dash.maidsafe.net", "~phil", "lifestufflocal", "linux",
                                    "32", "1", "1");
  // Find the latest file and donwload it together with its signature file
  EXPECT_TRUE(manager.FindLatestFile());
  EXPECT_EQ("lifestufflocal_linux_32_5_4" + extension, manager.file_to_download() + extension);

  std::string signature_file = "lifestufflocal_linux_32_5_4" + extension + ".sig";
  manager.SetFileToDownload(signature_file);
  EXPECT_TRUE(manager.UpdateCurrentFile(current_path));
  EXPECT_TRUE(boost::filesystem::exists(current_path / signature_file));
  EXPECT_FALSE(boost::filesystem::is_empty(current_path / signature_file));

  std::string file_to_download = "lifestufflocal_linux_32_5_4" + extension;
  manager.SetFileToDownload(file_to_download);
  EXPECT_TRUE(manager.UpdateCurrentFile(current_path));
  EXPECT_TRUE(boost::filesystem::exists(current_path / file_to_download));
  EXPECT_FALSE(boost::filesystem::is_empty(current_path / file_to_download));

  EXPECT_TRUE(manager.VerifySignature());

  boost::filesystem::remove(current_path / signature_file);
  boost::filesystem::remove(current_path / file_to_download);
}

TEST(DownloadManagerTest, BEH_VerificationFail) {
  boost::filesystem::path current_path(boost::filesystem::current_path());
  std::string extension = "";
  #ifdef _WINDOWS
    extension = ".exe";
  #endif
  maidsafe::DownloadManager manager("dash.maidsafe.net", "~phil", "lifestufflocal", "linux",
                                    "32", "1", "1");

  std::string signature_file = "lifestufflocal_linux_32_5_3" + extension + ".sig";
  manager.SetFileToDownload(signature_file);
  EXPECT_TRUE(manager.UpdateCurrentFile(current_path));
  EXPECT_TRUE(boost::filesystem::exists(current_path / signature_file));
  EXPECT_FALSE(boost::filesystem::is_empty(current_path / signature_file));

  std::string file_to_download = "lifestufflocal_linux_32_5_3" + extension;
  manager.SetFileToDownload(file_to_download);
  EXPECT_TRUE(manager.UpdateCurrentFile(current_path));
  EXPECT_TRUE(boost::filesystem::exists(current_path / file_to_download));
  EXPECT_FALSE(boost::filesystem::is_empty(current_path / file_to_download));

  EXPECT_FALSE(manager.VerifySignature());

  boost::filesystem::remove(current_path / signature_file);
  boost::filesystem::remove(current_path / file_to_download);
}

}  // namespace test

}  // namespace maidsafe

int main(int argc, char **argv) {
  maidsafe::log::FilterMap filter;
  filter["*"] = maidsafe::log::kInfo;
  return ExecuteMain(argc, argv, filter);
}
