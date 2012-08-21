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
      maidsafe_public_key_(),
      io_service_(),
      resolver_(io_service_),
      query_(site_, protocol_),
      local_path_(),
      remote_path_(),
      files_in_manifest_(),
      latest_local_version_("0.00.00") {
  boost::system::error_code error_code;
  fs::path temp_path(fs::unique_path(fs::temp_directory_path(error_code)));
  if (!fs::exists(temp_path, error_code))
    fs::create_directories(temp_path, error_code);
  if (error_code) {
    LOG(kError) << "Problem establishing temporary path for downloads.";
  } else {
    local_path_ = temp_path;
  }
#ifdef USE_TEST_KEYS
  LOG(kError) << "Using the test keys.";
  std::string public_key(DownloadFileToMemory("public_key.dat"));
  asymm::DecodePublicKey(public_key, &maidsafe_public_key_);
#else
  LOG(kError) << "Using the production keys.";
  asymm::DecodePublicKey(detail::kMaidSafePublicKey, &maidsafe_public_key_);
#endif
  if (!asymm::ValidateKey(maidsafe_public_key_))
    LOG(kError) << "MaidSafe public key invalid";
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

int DownloadManager::Update(std::vector<std::string>& updated_files) {
  std::string latest_remote_version(RetrieveLatestRemoteVersion());
  LOG(kVerbose) << "Latest local version is " << latest_local_version_;
  LOG(kVerbose) << "Latest remote version is " << latest_remote_version;
  if (detail::VersionToInt(latest_remote_version) > detail::VersionToInt(latest_local_version_)) {
    fs::path remote_update_path(detail::kThisPlatform().UpdatePath() / latest_remote_version);
    RetrieveManifest(remote_update_path);
    if (remote_path_.empty() || files_in_manifest_.empty()) {
      LOG(kError) << "Manifest was not successfully retrieved";
      return kManifestFailure;
    }
  }
  for (auto file : files_in_manifest_) {
    if (!GetAndVerifyFile((remote_path_ / file).string(), local_path_)) {
      LOG(kError) << "Failed to get and verify file: " << file;
      return kDownloadFailure;
    }
    LOG(kInfo) << "Updated file: " << file;
    updated_files.push_back(file);
  }
  latest_local_version_ = latest_remote_version;
  return kSuccess;
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

void DownloadManager::RetrieveManifest(const fs::path& manifest_location) {
  std::vector<std::string> files;
  if (!GetAndVerifyFile((manifest_location / "manifest").string(), local_path_)) {
    LOG(kError) << "Failed to download manifest file";
    return;
  }
  std::string manifest_content;
  if (!ReadFile(local_path_ / "manifest", &manifest_content)) {
    LOG(kError) << "Failed to read downloaded manifest file";
    return;
  }
  boost::split(files, manifest_content, boost::is_any_of("\n"));
  remote_path_ = manifest_location;
  files_in_manifest_ = files;
}

bool DownloadManager::GetAndVerifyFile(const std::string& file, const fs::path& directory) {
  std::string signature(DownloadFileToMemory(file + detail::kSignatureExtension));
  if (signature.empty()) {
    LOG(kWarning) << "Failed to download signature for file " << file;
    return false;
  }
  if (!DownloadFileToDisk(file, directory)) {
    return false;
  }
  std::string file_contents;
  ReadFile(directory / file, &file_contents);
  if (file_contents.empty()) {
    LOG(kWarning) << "Failed to download " << file;
    return false;
  }

  int result(asymm::CheckSignature(file_contents, signature, maidsafe_public_key_));
  if (result != kSuccess)  {
    LOG(kError) << "Signature of " << file << " is invalid. Removing file.  Check returned "
                << result;
    boost::system::error_code error;
    fs::remove(directory / file, error);
    if (error)
      LOG(kError) << "Filed to remove file " << file << " with invalid signature.";
    return false;
  }
  LOG(kVerbose) << "Signature of " << file << " is valid.";

  return true;
}

bool DownloadManager::PrepareDownload(const std::string& file_name,
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
    request_stream << "GET /" << location_ << "/" << file_name << " HTTP/1.0\r\n";
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
      LOG(kError) << "Error downloading " << site_ << "/" << location_ << "/" << file_name
                  << "  Invalid response.";
      return false;
    }
    if (status_code != 200) {
      LOG(kError) << "Error downloading " << site_ << "/" << location_ << "/" << file_name
                  << "  Returned " << status_code;
      return false;
    }
    // Read the response headers, which are terminated by a blank line.
    /*boost::asio::read_until(socket_, *response, "\r\n\r\n");*/
    // Process the response headers.
    std::string header;
    while (std::getline(*response_stream, header)) {
      if (header == "\r")
        break;
    }
  } catch(const std::exception &e) {
    LOG(kError) << "Error preparing downloading of " << site_ << "/" << location_ << "/"
                << file_name << "  : " << e.what();
    return false;
  }
  return true;
}

bool DownloadManager::DownloadFileToDisk(const std::string& file_name,
                                         const fs::path& directory) {
  ip::tcp::socket socket(io_service_);
  std::vector<char> char_buffer(1024);
  asio::streambuf response_buffer(1024);
  std::istream response_stream(&response_buffer);
  if (!PrepareDownload(file_name, &response_buffer, &response_stream, &socket))
    return false;
  try {
    boost::filesystem::ofstream file_out(directory / file_name,
                                         std::ios::out | std::ios::trunc | std::ios::binary);
    if (!file_out.good()) {
      LOG(kError) << "DownloadFileToDisk: Can't get ofstream created for "
                  << directory / file_name;
      return false;
    }
    boost::system::error_code error;
    // Read until EOF, copies 1024 byte chunks of file into memory at a time before adding to file
    std::streamsize length = response_stream.readsome(&char_buffer[0], std::streamsize(1024));
    std::string current_block(char_buffer.begin(), char_buffer.begin() + static_cast<int>(length));
    file_out.write(current_block.c_str(), current_block.size());
    std::size_t size = boost::asio::read(socket, boost::asio::buffer(char_buffer), error);
    while (size > 0) {
      if (error && error != boost::asio::error::eof) {
        LOG(kError) << "DownloadFileToDisk: Error downloading file " << file_name << ": "
                    << error.message();
        return false;
      }
      current_block.assign(char_buffer.begin(), char_buffer.begin() + size);
      file_out.write(current_block.c_str(), current_block.size());
      size = boost::asio::read(socket, boost::asio::buffer(char_buffer), error);
    }
    LOG(kInfo) << "DownloadFileToDisk: Finished downloading file " << file_name
               << ", closing file.";
    file_out.close();
    return true;
  } catch(const std::exception &e) {
    LOG(kError) << "DownloadFileToDisk: Exception " << directory / file_name
                << ": " << e.what();
    return false;
  }
}

std::string DownloadManager::DownloadFileToMemory(const std::string& file_name) {
  ip::tcp::socket socket(io_service_);
  asio::streambuf response_buffer;
  std::istream response_stream(&response_buffer);
  if (!PrepareDownload(file_name, &response_buffer, &response_stream, &socket))
    return "";
  try {
    // Read until EOF, puts whole file in memory, so this should be of manageable size
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

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
