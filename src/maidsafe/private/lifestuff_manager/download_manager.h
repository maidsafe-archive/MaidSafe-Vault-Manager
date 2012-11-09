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

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_DOWNLOAD_MANAGER_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_DOWNLOAD_MANAGER_H_

#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/asio/streambuf.hpp"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace test { class DownloadManagerTest; }


class DownloadManager {
 public:
  DownloadManager(const std::string& protocol,
                  const std::string& site,
                  const std::string& location);
  ~DownloadManager();
  // Retrieves the latest bootstrap file from the server.
  std::string GetBootstrapInfo();
  // Check for an update and carry out required updates. Populates updated_files with list of files
  // that were updated. Return code indicates success/type of failure.
  int Update(std::vector<boost::filesystem::path>& updated_files);
  std::string latest_local_version() const { return latest_local_version_; }
  std::string latest_remote_version() const { return latest_remote_version_; }
  friend class test::DownloadManagerTest;

 private:
  bool InitialiseLocalPath();
  bool InitialisePublicKey();
  int GetAndCheckLatestRemoteVersion();
  bool GetManifest(std::vector<std::string>& files_in_manifest);
  void GetNewFiles(const std::vector<std::string>& files_in_manifest,
                   std::vector<boost::filesystem::path>& updated_files);
  std::string GetAndVerifyFile(const boost::filesystem::path& remote_path);
  bool PrepareDownload(const boost::filesystem::path& remote_path,
                       boost::asio::streambuf& response_buffer,
                       std::istream& response_stream,
                       boost::asio::ip::tcp::socket& socket);
  bool CheckResponse(const boost::filesystem::path& remote_path, std::istream& response_stream);
  std::string DownloadFile(const boost::filesystem::path& remote_path);

  std::string protocol_, site_, location_, latest_local_version_, latest_remote_version_;
  asymm::PublicKey maidsafe_public_key_;
  boost::asio::io_service io_service_;
  boost::asio::ip::tcp::resolver resolver_;
  boost::asio::ip::tcp::resolver::query query_;
  boost::filesystem::path local_path_, latest_remote_path_;
  bool initialised_;
};

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_DOWNLOAD_MANAGER_H_
