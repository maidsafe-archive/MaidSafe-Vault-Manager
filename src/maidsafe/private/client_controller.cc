/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <boost/array.hpp>

#include <thread>
#include <chrono>
#include <iostream>

#include "maidsafe/private/client_controller.h"
#include "maidsafe/private/vault_identity_info.pb.h"
#include "maidsafe/private/vault_manager.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace maidsafe {
namespace priv {



  ClientController::ClientController() : port_(5483),
                                         thd_(),
                                         io_service_(),
                                         resolver_(io_service_),
                                         query_("", ""),
                                         endpoint_iterator_(),
                                         socket_(io_service_) {}

  ClientController::~ClientController() {}


  void ClientController::ConnectToManager() {
    // resolver_ = bai::tcp::resolver(io_service_);
    std::cout << "IN ConnectToManager " << std::endl;
    while (true) {
      try {
        std::cout << "PORT: " << boost::lexical_cast<std::string>(port_) << std::endl;
        query_ = bai::tcp::resolver::query("127.0.0.1", boost::lexical_cast<std::string>(port_));
        boost::system::error_code ec;
        endpoint_iterator_ = resolver_.resolve(query_, ec);
        bai::tcp::resolver::iterator end;
        // socket_ = bai::tcp::socket(io_service_);
        boost::system::error_code error = boost::asio::error::host_not_found;
        while (error && endpoint_iterator_ != end) {
          std::cout << "IN CONNECT LOOP " << std::endl;
          socket_.close();
          socket_.connect(*endpoint_iterator_, error);
          ++endpoint_iterator_;
        }
        if (error)
          throw boost::system::system_error(error);
        } catch(std::exception& e) {
        LOG(kError) << "expection thrown in ConnectToManager: " << e.what();
      }
      // ATTEMPT HELLO
      char message_type(static_cast<char>(MessageType::kHelloFromClient));
      std::string hello_string(1, message_type);
      maidsafe::priv::ClientHello hello;
      hello.set_hello("hello");
      hello_string += hello.SerializeAsString();
      boost::system::error_code ignored_error;
      boost::asio::write(socket_, boost::asio::buffer(hello_string), ignored_error);
      std::string hello_response_string;
      boost::system::error_code error = boost::asio::error::host_not_found;
      std::cout << "Hello attempt on " << port_ << ", awaiting response" << std::endl;
      try {
        for (;;) {
          std::cout << "IN RECEIVE LOOP " << std::endl;
          boost::array<char, 128> buf;
          size_t len = socket_.read_some(boost::asio::buffer(buf), error);
          std::cout << "AFTER READ SOME " << std::endl;
          if (error == boost::asio::error::eof)
            break;  // Connection closed cleanly by peer.
          else if (error)
            throw boost::system::system_error(error);
          hello_response_string.append(buf.data(), len);
        }
      } catch(std::exception& e) {
        std::cout << "ERROR: " << e.what() << std::endl;
      }
      if (static_cast<MessageType>(hello_response_string[0])
          == MessageType::kHelloResponseToClient) {
        ClientHelloResponse response;
        if (response.ParseFromString(hello_response_string.substr(1))) {
          if (response.hello_response() == "hello response")
            break;
        }
      }
      // IF SUCCESSFUL
      //   BREAK
    }
  }

  bool ClientController::StartVault(const maidsafe::asymm::Keys& /*keys*/,
                                    const std::string& /*account_name*/) {
    std::cout << "IN VaultController Start" << std::endl;
    try {
      thd_ = boost::thread([=] {
                                ConnectToManager();
                                  /*ListenForStopTerminate(shared_mem_name, pid, stop_callback);*/
                              });
    } catch(std::exception& e)  {
      std::cout << e.what() << "\n";
      return false;
    }
    if (thd_.joinable())
      thd_.join();
    return true;
  }

  bool ClientController::StopVault(const maidsafe::asymm::PlainText& /*data*/,
                                   const maidsafe::asymm::Signature& /*signature*/,
                                   const maidsafe::asymm::Identity& /*identity*/) { return false; }
}  // namespace priv

}  // namespace maidsafe

