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

#include "maidsafe/private/process_management/download_manager.h"

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

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/process_management/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace process_management {

DownloadManager::DownloadManager(const std::string& protocol,
                                 const std::string& site,
                                 const std::string& location)
    : protocol_(protocol),
      site_(site),
      location_(location),
      latest_local_version_("0.00.00"),
      maidsafe_public_key_(),
      io_service_(),
      resolver_(io_service_),
      query_(site_, protocol_),
      local_path_() {
  boost::system::error_code error_code;
  fs::path temp_path(fs::temp_directory_path(error_code) /
                     fs::unique_path("%%%%-%%%%-%%%%-%%%%", error_code));
  LOG(kError) << "temp_path: " << temp_path;
  if (!fs::exists(temp_path, error_code))
    fs::create_directories(temp_path, error_code);
  if (error_code) {
    LOG(kError) << "Problem establishing temporary path for downloads.";
  } else {
    local_path_ = temp_path;
  }
#ifdef USE_TEST_KEYS
  LOG(kError) << "Using the test keys.";
  std::string serialised_public_key(DownloadFileToMemory("public_key.dat"));
  if (serialised_public_key.empty())
    LOG(kError) << "Failure to retrieve key from server.";
  asymm::DecodePublicKey(serialised_public_key, &maidsafe_public_key_);
  if (!asymm::ValidateKey(maidsafe_public_key_))
    LOG(kError) << "Failure to decode retrieved serialised key.";
#else
  LOG(kError) << "Using the production keys.";
  asymm::DecodePublicKey(detail::kMaidSafePublicKey, &maidsafe_public_key_);
#endif
  if (!asymm::ValidateKey(maidsafe_public_key_))
    LOG(kError) << "MaidSafe public key invalid";
}

DownloadManager::~DownloadManager() {
  boost::system::error_code error_code;
  fs::remove_all(local_path_, error_code);
}

std::string DownloadManager::RetrieveBootstrapInfo() {
  if (!GetAndVerifyFile(detail::kBootstrapNodesFilename,
                        local_path_ / detail::kBootstrapNodesFilename)) {
    LOG(kError) << "Failed to download bootstrap file";
    return "";
  }

  std::string bootstrap_content;
  if (!ReadFile(local_path_ / detail::kBootstrapNodesFilename, &bootstrap_content)) {
    LOG(kError) << "Failed to read downloaded bootstrap file";
    return "";
  }

  return bootstrap_content;
}

int DownloadManager::Update(std::vector<std::string>& updated_files) {
  std::string latest_remote_version(RetrieveLatestRemoteVersion());
  LOG(kVerbose) << "Latest local version is " << latest_local_version_;
  LOG(kVerbose) << "Latest remote version is " << latest_remote_version;

  std::vector<std::string> files_in_manifest;
  if (detail::VersionToInt(latest_remote_version) <= detail::VersionToInt(latest_local_version_)) {
    LOG(kInfo) << "No version change.";
    return kSuccess;
  }

  fs::path remote_update_path(detail::kThisPlatform().UpdatePath() / latest_remote_version);
  if (!RetrieveManifest(remote_update_path / detail::kManifestFilename, files_in_manifest) ||
      files_in_manifest.empty()) {
    LOG(kError) << "Manifest was not successfully retrieved";
    return kManifestFailure;
  }

  for (auto file : files_in_manifest) {
    if (!GetAndVerifyFile(remote_update_path / file, local_path_ / file)) {
      LOG(kError) << "Failed to get and verify file: " << file;
      updated_files.clear();
      return kDownloadFailure;
    }
    LOG(kInfo) << "Updated file: " << file;
    updated_files.push_back(file);
  }
  latest_local_version_ = latest_remote_version;

  return kSuccess;
}

std::string DownloadManager::RetrieveLatestRemoteVersion() {
  if (!GetAndVerifyFile(detail::kVersionFilename, local_path_ / detail::kVersionFilename)) {
    LOG(kError) << "Failed to download version file";
    return "";
  }
  std::string version_content;
  if (!ReadFile(local_path_ / detail::kVersionFilename, &version_content)) {
    LOG(kError) << "Failed to read downloaded version file";
    return "";
  }
  return version_content.substr(0, version_content.size() - 1);
}

bool DownloadManager::RetrieveManifest(const fs::path& manifest_download_path,
                                       std::vector<std::string>& files_in_manifest) {
  if (!GetAndVerifyFile(manifest_download_path, local_path_ / detail::kManifestFilename)) {
    LOG(kError) << "Failed to download manifest file";
    return false;
  }
  std::string manifest_content;
  if (!ReadFile(local_path_ / detail::kManifestFilename, &manifest_content)) {
    LOG(kError) << "Failed to read downloaded manifest file";
    return false;
  }
  boost::split(files_in_manifest, manifest_content, boost::is_any_of("\n"));
  files_in_manifest.erase(files_in_manifest.end() - 1);

#ifdef DEBUG
  for (std::string file : files_in_manifest)
    LOG(kInfo) << "file in manifest: " << file;
#endif
  return true;
}

bool DownloadManager::GetAndVerifyFile(const fs::path& from_path, const fs::path& to_path) {
  std::string signature(DownloadFileToMemory(from_path.string() + detail::kSignatureExtension));
  if (signature.empty()) {
    LOG(kWarning) << "Failed to download signature for file " << from_path;
    return false;
  }

  if (!DownloadFileToDisk(from_path, to_path)) {
    LOG(kWarning) << "Failed to download file " << from_path;
    return false;
  }

  int result(asymm::CheckFileSignature(to_path, signature, maidsafe_public_key_));
  if (result != kSuccess)  {
    LOG(kError) << "Signature of " << to_path << " is invalid. Removing file: " << result;
    boost::system::error_code error;
    fs::remove(to_path, error);
    if (error)
      LOG(kError) << "Filed to remove file " << to_path << " with invalid signature.";
    return false;
  }
  LOG(kVerbose) << "Signature of " << to_path << " is valid.";

  return true;
}

bool DownloadManager::PrepareDownload(const fs::path& from_path,
                                      asio::streambuf* response_buffer,
                                      std::istream* response_stream,
                                      ip::tcp::socket* socket) {
  try {
    asio::streambuf request_buffer;
    std::ostream request_stream(&request_buffer);
    asio::connect(*socket, resolver_.resolve(query_));
    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    request_stream << "GET /" << location_ << "/" << from_path.string() << " HTTP/1.0\r\n";
    request_stream << "Host: " << site_ << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: close\r\n\r\n";
    // Send the request.
    asio::write(*socket, request_buffer);
    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.
    asio::read_until(*socket, *response_buffer, "\r\n");

    // Check that response is OK.
    std::string http_version;
    *response_stream >> http_version;
    unsigned int status_code;
    *response_stream >> status_code;

    std::string status_message;
    std::getline(*response_stream, status_message);
    if (!(*response_stream) || http_version.substr(0, 5) != "HTTP/") {
      LOG(kError) << "Error downloading " << site_ << "/" << location_ << "/" << from_path
                  << "  Invalid response.";
      return false;
    }
    if (status_code != 200) {
      LOG(kError) << "Error downloading " << site_ << "/" << location_ << "/" << from_path
                  << "  Returned " << status_code;
      return false;
    }

    // Process the response headers.
    std::string header;
    while (std::getline(*response_stream, header)) {
      if (header == "\r")
        break;
    }
  }
  catch(const std::exception &e) {
    LOG(kError) << "Error preparing downloading of " << site_ << "/" << location_ << "/"
                << from_path << "  : " << e.what();
    return false;
  }

  return true;
}

bool DownloadManager::DownloadFileToDisk(const fs::path& from_path, const fs::path& to_path) {
  ip::tcp::socket socket(io_service_);
  std::vector<char> char_buffer(1024);
  asio::streambuf response_buffer(1024);
  std::istream response_stream(&response_buffer);

  if (!PrepareDownload(from_path, &response_buffer, &response_stream, &socket)) {
    LOG(kError) << "Failed to prepare download for " << from_path;
    return false;
  }

  try {
    std::ofstream file_out(to_path.c_str(), std::ios::trunc | std::ios::binary);
    if (!file_out.good()) {
      LOG(kError) << "DownloadFileToDisk: Can't get ofstream created for " << to_path;
      return false;
    }

    boost::system::error_code error;
    // Read until EOF, copies 1024 byte chunks of file into memory at a time before adding to file
    std::streamsize length(response_stream.readsome(&char_buffer[0], std::streamsize(1024)));
    std::string current_block(char_buffer.begin(), char_buffer.begin() + static_cast<int>(length));
    file_out.write(current_block.c_str(), current_block.size());

    std::size_t size(boost::asio::read(socket, boost::asio::buffer(char_buffer), error));
    while (size > 0) {
      if (error && error != boost::asio::error::eof) {
        LOG(kError) << "DownloadFileToDisk: Error downloading file " << from_path << ": "
                    << error.message();
        return false;
      }
      current_block.assign(char_buffer.begin(), char_buffer.begin() + size);
      file_out.write(current_block.c_str(), current_block.size());
      size = boost::asio::read(socket, boost::asio::buffer(char_buffer), error);
    }
    LOG(kInfo) << "DownloadFileToDisk: Finished downloading file " << to_path
               << ", closing file.";
    file_out.close();
  }
  catch(const std::exception &e) {
    LOG(kError) << "DownloadFileToDisk: Exception " << to_path << ": " << e.what();
    return false;
  }

  return true;
}

std::string DownloadManager::DownloadFileToMemory(const fs::path& from_path) {
  ip::tcp::socket socket(io_service_);
  asio::streambuf response_buffer;
  std::istream response_stream(&response_buffer);
  if (!PrepareDownload(from_path, &response_buffer, &response_stream, &socket)) {
    LOG(kError) << "Failed to prepare download for " << from_path;
    return "";
  }

  try {
    // Read until EOF, puts whole file in memory, so this should be of manageable size
    boost::system::error_code error_code;
    while (asio::read(socket, response_buffer, asio::transfer_at_least(1), error_code))
      boost::this_thread::interruption_point();
    if (error_code != asio::error::eof) {
      LOG(kWarning) << "Error downloading " << site_ << "/" << location_ << "/" << from_path
                    << ": " << error_code.message();
      return "";
    }
  }
  catch(const std::exception &e) {
    LOG(kError) << "Error downloading " << site_ << "/" << location_ << "/" << from_path
                << ": " << e.what();
    return "";
  }

  return std::string(asio::buffer_cast<const char*>(response_buffer.data()),
                     response_buffer.size());
}

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
