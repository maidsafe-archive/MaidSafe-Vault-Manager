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
  // If a newer version of current_file exists, is sucessfully downloaded to directory, and the
  // signature verified, then the new file name is returned, else an empty string.
  std::string UpdateAndVerify(const std::string& current_file,
                              const boost::filesystem::path& directory);

 private:
  bool GetAndVerifyFile(const std::string& file, const boost::filesystem::path& directory);
  std::string DownloadFile(const std::string& file_name);
  std::string protocol_;
  std::string site_;
  std::string location_;
  asymm::PublicKey maidsafe_public_key_;
  boost::asio::io_service io_service_;
  boost::asio::ip::tcp::resolver resolver_;
  boost::asio::ip::tcp::resolver::query query_;
};

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DOWNLOAD_MANAGER_H_
