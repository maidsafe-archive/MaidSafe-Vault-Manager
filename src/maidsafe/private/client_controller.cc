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
                                         socket_(io_service_),
                                         transport_(io_service_),
                                         message_handler_() {}

  ClientController::~ClientController() {}


  void ClientController::ConnectToManager(uint16_t port) {
    // resolver_ = bai::tcp::resolver(io_service_);
    std::cout << "IN ConnectToManager " << std::endl;
    message_handler_.SetCallback(
        boost::bind(&maidsafe::priv::ClientController::ConnectToManagerCallback, this, _1, _2, _3));
    transport_.on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                          &message_handler_, _1, _2, _3, _4));
    Endpoint endpoint("127.0.0.1", port);
    int message_type(static_cast<int>(VaultManagerMessageType::kHelloFromClient));
    std::string hello_string;
    maidsafe::priv::ClientHello hello;
    hello.set_hello("hello");
    hello_string = message_handler_.MakeSerialisedWrapperMessage(message_type,
                                                                  hello.SerializeAsString());
    transport_.Send(hello_string, endpoint, boost::posix_time::milliseconds(50));
  }

  void ClientController::ConnectToManagerCallback(const int &type,
                                                  const std::string& hello_response_string,
                                                  const Info& sender_info) {
    if (type == static_cast<int>(VaultManagerMessageType::kHelloResponseToClient)) {
      ClientHelloResponse response;
      if (response.ParseFromString(hello_response_string)) {
        if (response.hello_response() == "hello response") {
          port_ = sender_info.endpoint.port;
          return;
        }
      }
    }
    ConnectToManager(sender_info.endpoint.port + 1);
  }

  bool ClientController::StartVault(const maidsafe::asymm::Keys& /*keys*/,
                                    const std::string& /*account_name*/) {
    std::cout << "IN VaultController Start" << std::endl;
    try {
      thd_ = boost::thread([=] {
                                ConnectToManager(port_);
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

