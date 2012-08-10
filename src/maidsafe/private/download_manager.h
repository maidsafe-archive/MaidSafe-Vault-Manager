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

#ifndef MAIDSAFE_PRIVATE_DOWNLOAD_MANAGER_H_
#define MAIDSAFE_PRIVATE_DOWNLOAD_MANAGER_H_

#include <istream>
#include <string>

#include "boost/asio/streambuf.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/tokenizer.hpp"


namespace maidsafe {

namespace priv {

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
                  std::string current_major_version,  // e.g. 123
                  std::string current_minor_version,  // e.g. 123
                  std::string current_patchlevel);  // e.g. 234
  void SetSiteName(std::string site) { site_ = site; }
  void SetLocation(std::string location) { location_ = location; }
  void SetProtocol(std::string protocol = "http");
  void SetNameToDownload(std::string name) { name_ = name; }
  void SetCurrentMajorVersionToUpdate(std::string version) { current_major_version_ = version; }
  void SetCurrentMinorVersionToUpdate(std::string version) { current_minor_version_ = version; } // UNITL HERE
  void SetCurrentPatchLevelToUpdate(std::string patchlevel) { current_patchlevel_ = patchlevel; }
  void SetPlatformToUpdate(std::string platform) { platform_ = platform; }
  void SetFileToDownload(std::string file_to_download) { file_to_download_ = file_to_download; }
  void ClearFileToDownload() { file_to_download_.clear(); }
  std::string file_to_download() const { return file_to_download_; }
  bool FileIsValid(std::string file) const;
  bool FileIsLaterThan(std::string file1, std::string file2) const;
  bool FindLatestFile();
  bool UpdateCurrentFile(boost::filesystem::path directory);
  bool VerifySignature() const;

 private:
  typedef boost::tokenizer<boost::char_separator<char>> Tokens;
  bool FileIsUseful(std::string file) const;
  bool GetFileBuffer(const std::string& file_path,
                     boost::asio::streambuf* response,
                     std::istream* response_stream,
                     boost::asio::ip::tcp::socket* socket) const;
  std::string site_;
  std::string location_;
  std::string name_;
  std::string platform_;
  std::string current_major_version_;
  std::string current_minor_version_;
  std::string current_patchlevel_;
  std::string protocol_;
  std::string file_to_download_;
  std::string maidsafe_public_key_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DOWNLOAD_MANAGER_H_
