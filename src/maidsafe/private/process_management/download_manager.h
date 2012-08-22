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

#ifndef MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_DOWNLOAD_MANAGER_H_
#define MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_DOWNLOAD_MANAGER_H_

#include <string>
#include <vector>

#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/asio/streambuf.hpp"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

namespace process_management {

class DownloadManager {
 public:
  DownloadManager(const std::string& protocol,
                  const std::string& site,
                  const std::string& location);
  // Retrieves the latest bootstrap file from the server.
  std::string RetrieveBootstrapInfo();
  // Check for an update and carry out required updates. Populates updated_files with list of files
  // that were updated. Return code indicates success/type of failure.
  int Update(std::vector<std::string>& updated_files);
  // Returns the local path to which the DownloadManager downloads files.
  boost::filesystem::path GetLocalPath() const { return local_path_; }
  // Returns the remote path from which the DownloadManager downloads the files in the manifest.
  boost::filesystem::path GetRemotePath() const { return remote_path_; }
  void SetLatestLocalVersion(const std::string& version) { latest_local_version_ = version; }
  std::string latest_local_version() const { return latest_local_version_; }

 private:
  // Get the version of the files on the update server
  std::string RetrieveLatestRemoteVersion();
  // Retrieves the manifest file from the specified location.
  void RetrieveManifest(const boost::filesystem::path& manifest_location,
                        std::vector<std::string>& files_in_manifest);
  bool GetAndVerifyFile(const std::string& file, const boost::filesystem::path& directory);
  bool PrepareDownload(const std::string& file_name,
                       boost::asio::streambuf* response_buffer,
                       std::istream* response_stream,
                       boost::asio::ip::tcp::socket* socket);
  bool DownloadFileToDisk(const std::string& file_name, const boost::filesystem::path& directory);
  std::string DownloadFileToMemory(const std::string& file_name);

  std::string protocol_, site_, location_, latest_local_version_;
  asymm::PublicKey maidsafe_public_key_;
  boost::asio::io_service io_service_;
  boost::asio::ip::tcp::resolver resolver_;
  boost::asio::ip::tcp::resolver::query query_;
  boost::filesystem::path local_path_, remote_path_;
};

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_DOWNLOAD_MANAGER_H_
