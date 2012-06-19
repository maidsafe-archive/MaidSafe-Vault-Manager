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

#include "maidsafe/private/download_manager.h"

#include <fstream>
#include <iostream>
#include <istream>
#include <ostream>
#include <string>
#include <vector>

#include "boost/archive/text_iarchive.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

namespace bai = boost::asio::ip;

namespace maidsafe {

DownloadManager::DownloadManager(std::string site,
                                 std::string name,
                                 std::string platform,
                                 std::string cpu_size,
                                 std::string current_version,
                                 std::string current_patchlevel) :
  site_(site),
  name_(name),
  current_version_(current_version),
  current_patchlevel_(current_patchlevel_),
  protocol_("http") {}

bool DownloadMananger::Exists() {
  std::ostringstream bootstrap_stream(std::ios::binary);
  try {
    boost::asio::io_service io_service;
    bai::tcp::resolver resolver(io_service);
    bai::tcp::resolver::query query(site_, protocol_);
    bai::tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
    // Try each endpoint until we successfully establish a connection.
    bai::tcp::socket socket(io_service);
    boost::asio::connect(socket, endpoint_iterator);
    // Form the request. We specify the "Connection: close" header so that the
    // server will close the socket after transmitting the response. This will
    // allow us to treat all data up until the EOF as the content.
    boost::asio::streambuf request;
    std::ostream request_stream(&request);
    request_stream << "GET /bootstrap HTTP/1.0\r\n";
    request_stream << "Host: " << site_ << "\r\n";
    request_stream << "Accept: */*\r\n";  // TODO(dirvine) check files here
    request_stream << "Connection: close\r\n\r\n";
    // Send the request.
    boost::asio::write(socket, request);
    // Read the response status line. The response streambuf will automatically
    // grow to accommodate the entire line. The growth may be limited by passing
    // a maximum size to the streambuf constructor.
    boost::asio::streambuf response;
    boost::asio::read_until(socket, response, "\r\n");
    // Check that response is OK.
    std::istream response_stream(&response);
    std::string http_version;
    response_stream >> http_version;
    unsigned int status_code;
    response_stream >> status_code;
    std::string status_message;
    std::getline(response_stream, status_message);
    if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
      DLOG(ERROR) << "Error downloading file list: Invalid response";
      return kGeneralError;
    }
    if (status_code != 200) {
      DLOG(ERROR) << "Error downloading file list: Response returned "
                  << "with status code " << status_code;
      return kGeneralError;
    }

    // Read the response headers, which are terminated by a blank line.
    boost::asio::read_until(socket, response, "\r\n\r\n");

    // Process the response headers.
    std::string header;
    while (std::getline(response_stream, header)) {
      if (header == "\r")
        break;
    }

    // Write whatever content we already have to output.
    if (response.size() > 0)
      bootstrap_stream << &response;

    // Read until EOF, writing data to output as we go.
    boost::system::error_code error;
    while (boost::asio::read(socket,
                             response,
                             boost::asio::transfer_at_least(1),
                             error))
      bootstrap_stream << &response;

    if (error != boost::asio::error::eof) {
      DLOG(ERROR) << "Error downloading bootstrap file: " << error.message();
      return error.value();
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Exception: " << e.what();
    return kGeneralException;
  }



  return true;
}

}  // namespace maidsafe
