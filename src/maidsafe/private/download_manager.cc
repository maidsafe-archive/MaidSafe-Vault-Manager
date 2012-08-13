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
#include <iterator>
#include <ostream>
#include <vector>

#include "boost/asio/connect.hpp"
#include "boost/asio/read.hpp"
#include "boost/asio/read_until.hpp"
#include "boost/asio/write.hpp"
#include "boost/lexical_cast.hpp"
#include "boost/filesystem/fstream.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"


namespace bai = boost::asio::ip;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

DownloadManager::DownloadManager()
    : site_(),
      location_(),
      name_(),
      platform_(),
      current_major_version_(),
      current_minor_version_(),
      current_patchlevel_(),
      protocol_(),
      file_to_download_(),
      maidsafe_public_key_(DecodeFromHex("308201080282010100e97d80923586b7ac2c72b8087598af9bd054249879b8d99c249af05ae4338dcd969c440a39a79d8caba34a7bc5571e92557c1ede11d48ba34dc464b7f7f358092d391622a2a20c183d6f2969827e537e6dd650f7f17cfa9ca8b3e90b86212e0718855468286d353d0279e6cbdc70b338fa56362b15c7534e2ee1ff6271c8a98b09f7bab16c47576826aefa2485720c0bf30c28deb5d5eb583fdfb3b4182f4ba83b7b004d414bf7ae4c54402ed86064096ba2cec02fcaf3368c9b04700e5e7a55f2d16286ad890d7c39395a04ccd27f7302ff55ba5eea4f5ae9d81371db9bb32dcbecca9a1f96c6a58bd9b63e2bfcf89ecaf1b2b0d29e798892968d0f0057e177020111")) {}  // NOLINT

DownloadManager::DownloadManager(std::string site,
                                 std::string location,
                                 std::string name,
                                 std::string platform,
                                 std::string current_major_version,
                                 std::string current_minor_version,
                                 std::string current_patchlevel)
    : site_(site),
      location_(location),
      name_(name),
      platform_(platform),
      current_major_version_(current_major_version),
      current_minor_version_(current_minor_version),
      current_patchlevel_(current_patchlevel),
      protocol_("http"),
      file_to_download_(),
      maidsafe_public_key_(DecodeFromHex("308201080282010100e97d80923586b7ac2c72b8087598af9bd054249879b8d99c249af05ae4338dcd969c440a39a79d8caba34a7bc5571e92557c1ede11d48ba34dc464b7f7f358092d391622a2a20c183d6f2969827e537e6dd650f7f17cfa9ca8b3e90b86212e0718855468286d353d0279e6cbdc70b338fa56362b15c7534e2ee1ff6271c8a98b09f7bab16c47576826aefa2485720c0bf30c28deb5d5eb583fdfb3b4182f4ba83b7b004d414bf7ae4c54402ed86064096ba2cec02fcaf3368c9b04700e5e7a55f2d16286ad890d7c39395a04ccd27f7302ff55ba5eea4f5ae9d81371db9bb32dcbecca9a1f96c6a58bd9b63e2bfcf89ecaf1b2b0d29e798892968d0f0057e177020111")) {}  // NOLINT

bool DownloadManager::FileIsValid(std::string file) const {
  Tokens tokens(file, boost::char_separator<char>("_"));
  Tokens tokens2(file, boost::char_separator<char>("."));
  if ((std::distance(tokens.begin(), tokens.end()) != 3)
       || (std::distance(tokens2.begin(), tokens2.end()) != 3)) {
    LOG(kError) << "File '" << file << "' has incorrect name format";
    return false;
  }
  LOG(kInfo) << "File '" << file << "' has correct name format";
  return true;
}

bool DownloadManager::FileIsLaterThan(std::string file1, std::string file2) const {
  LOG(kInfo) << "File 1 " << file1;
  LOG(kInfo) << "File 2 " << file2;
  if (file2.empty() || !FileIsValid(file2))
    return true;
  else if (file1.empty() || !FileIsValid(file1))
    return false;

  Tokens filetokens1(file1, boost::char_separator<char>("_"));
  Tokens filetokens2(file2, boost::char_separator<char>("_"));

  // skip past name and platform
  auto file_itr1(filetokens1.begin());
  auto file_itr2(filetokens2.begin());
  for (int i(0); i != 2; ++i, ++file_itr1, ++file_itr2) {}

  // Separate the information about the versions
  Tokens version_tokens1(*file_itr1, boost::char_separator<char>("."));
  Tokens version_tokens2(*file_itr2, boost::char_separator<char>("."));
  auto version_itr1(version_tokens1.begin());
  auto version_itr2(version_tokens2.begin());

  uint32_t major_version1, major_version2;

  try {
    major_version2 = boost::lexical_cast<uint32_t>(*version_itr2);
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return true;
  }

  try {
    major_version1 = boost::lexical_cast<uint32_t>(*version_itr1);
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return false;
  }

  if (major_version2 < major_version1)
    return true;

  uint32_t minor_version1, minor_version2;
  try {
    minor_version2 = boost::lexical_cast<uint32_t>(*(++version_itr2));
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return true;
  }

  try {
    minor_version1 = boost::lexical_cast<uint32_t>(*(++version_itr1));
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return false;
  }

  if (minor_version2 < minor_version1)
    return true;

  uint32_t patchlevel1, patchlevel2;

  try {
    patchlevel2 = boost::lexical_cast<uint32_t>(*(++version_itr2));
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return true;
  }

  try {
    patchlevel1 = boost::lexical_cast<uint32_t>(*(++version_itr1));
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return false;
  }

  return patchlevel2 < patchlevel1;
}

bool DownloadManager::FileIsUseful(std::string file) const {
  if (!FileIsValid(file))
    return false;

  Tokens file_tokens(file, boost::char_separator<char>("_"));
  auto fileitr(file_tokens.begin());

  if (name_ != *fileitr) {
    return false;
  }

  if (platform_ != *(++fileitr)) {
    return false;
  }

  uint32_t major_version, minor_version, patchlevel;
  Tokens version_tokens(*(++fileitr), boost::char_separator<char>("."));
  auto versionitr(version_tokens.begin());

  try {
    major_version = boost::lexical_cast<uint32_t>(*(versionitr));
    minor_version = boost::lexical_cast<uint32_t>(*(++versionitr));
    patchlevel = boost::lexical_cast<uint32_t>(*(++versionitr));
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return false;
  }

  if (current_major_version_.empty()) {
    LOG(kInfo) << "Empty version, getting any version from server";
    return true;
  }

  uint32_t current_major_version;
  try {
    current_major_version = boost::lexical_cast<uint32_t>(current_major_version_);
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return true;
  }

  LOG(kInfo) << "Latest major version is: " << current_major_version
             << " The one we are testing is: " << major_version;
  if (major_version != current_major_version)
    return major_version > current_major_version;

  uint32_t current_minor_version;
  try {
    current_minor_version = boost::lexical_cast<uint32_t>(current_minor_version_);
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return true;
  }

  LOG(kInfo) << "Latest minor version is: " << current_minor_version
             << " The one we are testing is: " << minor_version;
  if (minor_version != current_minor_version)
    return minor_version > current_minor_version;

  if (current_patchlevel_.empty()) {
    LOG(kInfo) << "Empty patchlevel, getting any patchlevel with current version from server";
    return true;
  }

  uint32_t current_patchlevel;
  try {
    current_patchlevel = boost::lexical_cast<uint32_t>(current_patchlevel_);
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kError) << e.what();
    return true;
  }

  return patchlevel > current_patchlevel;
}

bool DownloadManager::FindLatestFile() {
  boost::asio::io_service io_service;
  bai::tcp::resolver resolver(io_service);
  bai::tcp::resolver::query query(site_, protocol_);
  bai::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

  // Try each endpoint until we successfully establish a connection.
  bai::tcp::socket socket(io_service);
  boost::asio::connect(socket, endpoint_iterator);
  file_to_download_.clear();
  boost::asio::streambuf file_list_buffer;
  std::istream file_list_stream(&file_list_buffer);
  if (!GetFileBuffer("/" + location_ + "/file_list", &file_list_buffer, &file_list_stream,
      &socket)) {
    return false;
  }

  // Read until EOF, puts whole file list in memory but this should be of manageable size
  boost::system::error_code error;
  while (boost::asio::read(socket, file_list_buffer, boost::asio::transfer_at_least(1), error));
  if (error != boost::asio::error::eof) {
    LOG(kError) << "Error downloading list of latest file versions: " << error.message();
    return false;
  }

  std::string current_file;
  std::vector<std::string> files;
  while (std::getline(file_list_stream, current_file))
    files.push_back(current_file);

  auto itr(files.begin());
  std::string latest_file, next_file;
  for (; itr != files.end(); ++itr) {
    next_file = *itr;
    // THIS WILL PROBABLY CHANGE IF THERE ARE PROBLEMS WITH MACs
    boost::erase_all(next_file, ".exe");
    LOG(kInfo) << "Latest file: " << latest_file << "  Current file: " << next_file;  //  (*it);

    if (FileIsUseful(next_file) && FileIsLaterThan(next_file, latest_file)) {
      latest_file = next_file;
      LOG(kInfo) << latest_file << " is useful and is the latest.";
    }
  }

  if (latest_file.empty()) {
    LOG(kWarning) << "No more recent version of requested file " << name_
                  << " exists in latest file versions list";
    return false;
  }

  file_to_download_ = latest_file;
  LOG(kInfo) << "Found more recent version of file '" << name_ << "' on updates server";
  return true;
}

bool DownloadManager::UpdateCurrentFile(fs::path directory) {
  if (file_to_download_.empty()) {
    LOG(kError) << "The file to be downloaded has not yet been found, use FindLatestFile()";
    return false;
  }

  boost::asio::io_service io_service;
  bai::tcp::resolver resolver(io_service);
  bai::tcp::resolver::query query(site_, protocol_);
  bai::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);

  // Try each endpoint until we successfully establish a connection.
  bai::tcp::socket socket(io_service);
  boost::asio::connect(socket, endpoint_iterator);
  std::vector<char> char_buffer(1024);
  boost::asio::streambuf current_file_buffer(1024);
  std::istream current_file_stream(&current_file_buffer);
  if (!GetFileBuffer("/" + location_ + "/" + file_to_download_, &current_file_buffer,
      &current_file_stream, &socket)) {
    return false;
  }

  try {
    fs::ofstream file_out(directory / file_to_download_,
                          std::ios::out | std::ios::trunc | std::ios::binary);
    if (!file_out.good()) {
      LOG(kError) << "Can't get ofstream created for " << directory / file_to_download_;
      return false;
    }

    boost::system::error_code error;
    // Read until EOF, copies 1024 byte chunks of file into memory at a time before adding to file
    std::streamsize length = current_file_stream.readsome(&char_buffer[0], std::streamsize(1024));
    std::string current_block(char_buffer.begin(), char_buffer.begin() + static_cast<int>(length));
    file_out.write(current_block.c_str(), current_block.size());
    size_t size = boost::asio::read(socket, boost::asio::buffer(char_buffer), error);
    while (size > 0) {
      if (error && error != boost::asio::error::eof) {
        LOG(kError) << "UpdateCurrentFile: Error downloading file " << file_to_download_ << ": "
                    << error.message();
        return false;
      }
      current_block.assign(char_buffer.begin(), char_buffer.begin() + size);
      file_out.write(current_block.c_str(), current_block.size());
      size = boost::asio::read(socket, boost::asio::buffer(char_buffer), error);
    }
    LOG(kInfo) << "Finished downloading file " << file_to_download_ << ", closing file.";
    file_out.close();
  } catch(const std::exception &e) {
    LOG(kError) << "Failed to write file " << directory / file_to_download_ << ": " << e.what();
    return false;
  }

  return true;
}

bool DownloadManager::VerifySignature() const {
//   fs::path current_path(fs::current_path());
//   fs::path key_file("maidsafe_public");
  fs::path file(file_to_download_);
  fs::path sigfile(file_to_download_ + ".sig");
  std::string signature, data;

  if (!ReadFile(file, &data) || !ReadFile(sigfile, &signature)) {
    LOG(kInfo) << "Verify Signature - error reading file";
    return false;
  }

  asymm::PublicKey public_key;
  asymm::DecodePublicKey(maidsafe_public_key_, &public_key);

  if (!asymm::ValidateKey(public_key)) {
    LOG(kInfo) << "Verify Signature - public key invalid, aborting!!";
  }

  if (asymm::CheckSignature(data, signature, public_key) == 0)  {
    LOG(kInfo) << "Verify Signature - Signature valid";
  } else {
    LOG(kError) << "Verify Signature - Invalid signature";
    return false;
  }
  return true;
}

bool DownloadManager::GetFileBuffer(const std::string& file_path,
                                    boost::asio::streambuf* response,
                                    std::istream* response_stream,
                                    bai::tcp::socket* socket) const {
  boost::asio::streambuf request;
  std::ostream request_stream(&request);
  try {
    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    request_stream << "GET " << file_path <<" HTTP/1.0\r\n";
    request_stream << "Host: " << site_ << "\r\n";
    request_stream << "Accept: */*\r\n";
    request_stream << "Connection: close\r\n\r\n";
    // Send the request.
    boost::asio::write(*socket, request);
    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.
    boost::asio::read_until(*socket, *response, "\r\n");
    // Check that response is OK.
    std::string http_version;
    *response_stream >> http_version;
    unsigned int status_code;
    *response_stream >> status_code;
    std::string status_message;
    std::getline(*response_stream, status_message);
    if (!(*response_stream) || http_version.substr(0, 5) != "HTTP/") {
      LOG(kError) << "Error downloading file list: Invalid response";
      return false;
    }
    if (status_code != 200) {
      LOG(kError) << "Error downloading file list: Response returned " << status_code;
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
  }
  catch(const std::exception &e) {
    LOG(kError) << e.what();
    return false;
  }
  return true;
}

}  // namespace priv

}  // namespace maidsafe
