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

#include "maidsafe/private/download_manager.h"

#include <cstdint>
#include <istream>
#include <iterator>
#include <ostream>
#include <vector>

#include "boost/algorithm/string.hpp"
#include "boost/asio/connect.hpp"
#include "boost/asio/read.hpp"
#include "boost/asio/read_until.hpp"
#include "boost/asio/write.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/filesystem/fstream.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/return_codes.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/utils.h"


namespace asio = boost::asio;
namespace ip = asio::ip;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

DownloadManager::DownloadManager(const std::string& protocol,
                                 const std::string& site,
                                 const std::string& location)
    : protocol_(protocol),
      site_(site),
      location_(location),
      maidsafe_public_key_(),
      io_service_(),
      resolver_(io_service_),
      query_(site_, protocol_),
      local_path_(),
      remote_path_(),
      files_in_manifest_() {
  asymm::DecodePublicKey(detail::kMaidSafePublicKey, &maidsafe_public_key_);
  if (!asymm::ValidateKey(maidsafe_public_key_))
    LOG(kError) << "MaidSafe public key invalid";
  std::string prefix(RandomAlphaNumericString(8));
  boost::system::error_code error_code;
  fs::path temp_path(fs::unique_path(fs::temp_directory_path(error_code) / prefix));
  local_path_ = temp_path;
}

std::string DownloadManager::RetrieveBootstrapInfo() {
  if (!GetAndVerifyFile("bootstrap-global.dat", local_path_)) {
    LOG(kError) << "Failed to download bootstrap file";
    return "";
  }
  std::string bootstrap_content;
  if (!ReadFile(local_path_ / "bootstrap-global.dat", &bootstrap_content)) {
    LOG(kError) << "Failed to read downloaded bootstrap file";
    return "";
  }
  return bootstrap_content;
}

std::string DownloadManager::RetrieveLatestRemoteVersion() {
  if (!GetAndVerifyFile("version", local_path_)) {
    LOG(kError) << "Failed to download version file";
    return "";
  }
  std::string version_content;
  if (!ReadFile(local_path_ / "version", &version_content)) {
    LOG(kError) << "Failed to read downloaded version file";
    return "";
  }
  return version_content;
}

std::vector<std::string> DownloadManager::RetrieveManifest(fs::path manifest_location) {
  std::vector<std::string> files;
  if (!GetAndVerifyFile((manifest_location / "manifest").string(), local_path_)) {
    LOG(kError) << "Failed to download manifest file";
    return files;
  }
  std::string manifest_content;
  if (!ReadFile(local_path_ / "manifest", &manifest_content)) {
    LOG(kError) << "Failed to read downloaded manifest file";
    return files;
  }
  boost::split(files, manifest_content, boost::is_any_of("\n"));
  remote_path_ = manifest_location;
  files_in_manifest_ = files;
  return files;
}

std::vector<std::string> DownloadManager::UpdateFilesInManifest() {
  std::vector<std::string> updated_files;
  if (remote_path_.empty() || files_in_manifest_.empty()) {
    LOG(kError) << "Manifest has not yet been successfully retrieved";
  }
  for (auto file : files_in_manifest_) {
    if (!GetAndVerifyFile((remote_path_ / file).string(), local_path_)) {
      LOG(kError) << "Failed to get and verify file: " << file;
    } else {
      updated_files.push_back(file);
    }
  }
  return updated_files;
}

bool DownloadManager::GetAndVerifyFile(const std::string& file, const fs::path& directory) {
  std::string signature(DownloadFile(file + detail::kSignatureExtension));
  if (signature.empty()) {
    LOG(kWarning) << "Failed to download signature for file " << file;
    return false;
  }

  std::string file_contents(DownloadFile(file));
  if (file_contents.empty()) {
    LOG(kWarning) << "Failed to download " << file;
    return false;
  }

  int result(asymm::CheckSignature(file_contents, signature, maidsafe_public_key_));
  if (result != kSuccess)  {
    LOG(kError) << "Signature of " << file << " is invalid.  Check returned " << result;
    return false;
  }
  LOG(kVerbose) << "Signature of " << file << " is valid.";

  if (!WriteFile(directory / file, file_contents)) {
    LOG(kError) << "Failed to write " << directory / file;
    return false;
  }

  return true;
}

std::string DownloadManager::DownloadFile(const std::string& file_name) {
  ip::tcp::socket socket(io_service_);
  asio::streambuf request_buffer, response_buffer;
  std::istream response_stream(&response_buffer);
  std::ostream request_stream(&request_buffer);
  try {
    asio::connect(socket, resolver_.resolve(query_));
    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    request_stream << "GET /" << location_ << "/" << file_name << " HTTP/1.0\r\n";
    request_stream << "Host: " << site_ << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: close\r\n\r\n";
    // Send the request.
    asio::write(socket, request_buffer);
    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.
    asio::read_until(socket, response_buffer, "\r\n");
    // Check that response is OK.
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
      LOG(kError) << "Error downloading " << site_ << "/" << location_ << "/" << file_name
                  << "  Invalid response.";
      return "";
    }
    if (status_code != 200) {
      LOG(kError) << "Error downloading " << site_ << "/" << location_ << "/" << file_name
                  << "  Returned " << status_code;
      return "";
    }
    // Read the response headers, which are terminated by a blank line.
    /*asio::read_until(socket_, *response, "\r\n\r\n");*/
    // Process the response headers.
    std::string header;
    while (std::getline(response_stream, header)) {
      if (header == "\r")
        break;
    }

    // Read until EOF, puts whole file list in memory but this should be of manageable size
    boost::system::error_code error_code;
    while (asio::read(socket, response_buffer, asio::transfer_at_least(1), error_code))
      boost::this_thread::interruption_point();
    if (error_code != asio::error::eof) {
      LOG(kWarning) << "Error downloading " << site_ << "/" << location_ << "/" << file_name
                  << "  : " << error_code.message();
      return "";
    }
  }
  catch(const std::exception &e) {
    LOG(kError) << "Error downloading " << site_ << "/" << location_ << "/" << file_name
                << "  : " << e.what();
    return "";
  }

  const char* char_buffer = asio::buffer_cast<const char*>(response_buffer.data());
  return std::string(char_buffer, response_buffer.size());
}

}  // namespace priv

}  // namespace maidsafe
