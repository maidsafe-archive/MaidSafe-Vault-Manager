/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_PRIVATE_DOWNLOAD_MANAGER_H_
#define MAIDSAFE_PRIVATE_DOWNLOAD_MANAGER_H_
#include <fstream>
#include <iostream>
#include <istream>
#include <ostream>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio.hpp"
#include "boost/filesystem/path.hpp"

namespace bai = boost::asio::ip;

namespace maidsafe {
// assumes NAME-VERSION-PATCH naming convention
// passing "" will mean system ignores these and always downloads
// the file
class DownloadManager {
 public:
  DownloadManager();
  DownloadManager(std::string site,
                  std::string location,  // location of files on site
                  std::string name,  // eg maidsafe_vault / maidsafe_client
                  std::string platform,  // linux / osx / windows
                  std::string cpu_size,  // 64/32
                  std::string current_version,  // e.g. 123
                  std::string current_patchlevel);  // e.g. 234
  void SetSiteName(std::string site) { site_ = site; }
  void SetLocation(std::string location) { location_ = location; }
  void SetProtocol(std::string protocol = "http");
  void SetNameToDownload(std::string name) { name_ = name; }
  void SetCurrentVersionToUpdate(std::string version) { current_version_ = version; }
  void SetCurrentPatchLevelToUpdate(std::string patchlevel) { current_patchlevel_ = patchlevel; }
  void SetPlatformToUpdate(std::string platform) { platform_ = platform; }
  void SetCpuSizeToUpdate(std::string cpu_size) { cpu_size_ = cpu_size; }
  void SetFileToDownload(std::string file_to_download) { file_to_download_ = file_to_download; }
  void ClearFileToDownload() { file_to_download_ = ""; }
  std::string file_to_download() {return file_to_download_;}
  bool FindLatestFile();
  bool UpdateCurrentFile(boost::filesystem::path directory);
  bool FileIsValid(std::string file);
  bool FileIsLaterThan(std::string file1, std::string file2);
  bool VerifySignature();

 private:
  bool FileIsUseful(std::string file);
  bool GetFileBuffer(const std::string& file_path, boost::asio::streambuf* response,
                     std::istream* response_stream, bai::tcp::socket* socket);
  std::string site_;
  std::string location_;
  std::string name_;
  std::string platform_;
  std::string cpu_size_;
  std::string current_version_;
  std::string current_patchlevel_;
  std::string protocol_;
  std::string file_to_download_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DOWNLOAD_MANAGER_H_
