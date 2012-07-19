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
                                         mutex_(),
                                         cond_var_(),
                                         transport_(io_service_),
                                         message_handler_(),
                                         connected_to_manager_(false),
                                         vault_started_(false) {}

  ClientController::~ClientController() {}


  void ClientController::ConnectToManager(uint16_t port) {
    transport_.on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                          &message_handler_, _1, _2, _3, _4));
    transport_.on_error()->connect(boost::bind(&MessageHandler::OnError,
                                               &message_handler_, _1, _2));
    message_handler_.on_error()->connect(boost::bind(&ClientController::OnConnectError,
                                                     this, _1, _2));
    message_handler_.SetCallback(
          boost::bind(&ClientController::ConnectToManagerCallback, this, _1, _2, _3));
    std::string hello_string;
    Endpoint endpoint("127.0.0.1", port);
    std::cout << "IN ConnectToManager " << std::endl;
    int message_type(static_cast<int>(VaultManagerMessageType::kHelloFromClient));
    maidsafe::priv::ClientHello hello;
    hello.set_hello("hello");
    hello_string = message_handler_.MakeSerialisedWrapperMessage(message_type,
                                                                  hello.SerializeAsString());
    transport_.Send(hello_string, endpoint, boost::posix_time::milliseconds(50));
  }

  void ClientController::ConnectToManagerCallback(const int &type,
                                                  const std::string& hello_response_string,
                                                  const Info& sender_info) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      if (type == static_cast<int>(VaultManagerMessageType::kHelloResponseToClient)) {
        ClientHelloResponse response;
        if (response.ParseFromString(hello_response_string)) {
          if (response.hello_response() == "hello response") {
            port_ = sender_info.endpoint.port;
            connected_to_manager_ = true;
            cond_var_.notify_all();
            return;
          }
        }
      }
      if (!connected_to_manager_) {
        std::cout << "ConnectToManagerCallback: Couldn't parse response. Trying next port: "
                  << sender_info.endpoint.port + 1 << std::endl;
        ConnectToManager(sender_info.endpoint.port + 1);
      }
    }
  }

  void ClientController::OnConnectError(const TransportCondition &/*transport_condition*/,
                                        const Endpoint &remote_endpoint) {
    boost::mutex::scoped_lock lock(mutex_);
    if (!connected_to_manager_) {
      std::cout << "OnConnectError: Error sending or receiving connect message. Trying next port: "
                << remote_endpoint.port + 1 << std::endl;
      ConnectToManager(remote_endpoint.port + 1);
    }
  }

  void ClientController::OnStartVaultError(const TransportCondition &/*transport_condition*/,
                                        const Endpoint &/*remote_endpoint*/) {
    boost::mutex::scoped_lock lock(mutex_);
    if (!vault_started_) {
      std::cout << "OnStartVaultError: Error sending start vault message. " << std::endl;
    }
  }

  void ClientController::StartVaultRequest(const maidsafe::asymm::Keys& keys,
                                           const std::string& account_name) {
    message_handler_.on_error()->connect(boost::bind(&ClientController::OnStartVaultError,
                                                     this, _1, _2));
    message_handler_.SetCallback(
        boost::bind(&ClientController::StartVaultRequestCallback, this, _1, _2, _3));
    int message_type(static_cast<int>(VaultManagerMessageType::kStartRequestFromClient));
    maidsafe::priv::ClientStartVaultRequest request;
    std::string keys_string;
    asymm::SerialiseKeys(keys, keys_string);
    request.set_keys(keys_string);
    request.set_account_name(account_name);
    std::string request_string;
    request_string = message_handler_.MakeSerialisedWrapperMessage(message_type,
                                                                   request.SerializeAsString());
    Endpoint endpoint("127.0.0.1", port_);
    transport_.Send(request_string, endpoint, boost::posix_time::milliseconds(50));
  }

  void ClientController::StartVaultRequestCallback(const int &type,
                                                   const std::string& start_response_string,
                                                   const Info& /*sender_info*/) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      if (type == static_cast<int>(VaultManagerMessageType::kStartResponseToClient)) {
        ClientStartVaultResponse response;
        if (response.ParseFromString(start_response_string)) {
          if (response.result() == true) {
            vault_started_ = true;
            cond_var_.notify_all();
            return;
          }
        }
      }
    }
  }

  bool ClientController::StartVault(const maidsafe::asymm::Keys& keys,
                                    const std::string& account_name) {
    std::cout << "IN ClientController StartVault" << std::endl;
    try {
      thd_ = boost::thread([=] { ConnectToManager(port_); });  // NOLINT (Philip)
    } catch(std::exception& e)  {
      std::cout << e.what() << "\n";
      return false;
    }
    {
      boost::mutex::scoped_lock lock(mutex_);
      if (cond_var_.timed_wait(lock,
                              boost::posix_time::seconds(3),
                              [&]()->bool { return connected_to_manager_; })) {
        if (thd_.joinable())
          thd_.join();
      }
    }
    if (!connected_to_manager_)
      return false;
    try {
      thd_ = boost::thread([=] { StartVaultRequest(keys, account_name); });  // NOLINT (Philip)
    } catch(std::exception& e)  {
      std::cout << e.what() << "\n";
      return false;
    }
    {
      boost::mutex::scoped_lock lock(mutex_);
      if (cond_var_.timed_wait(lock,
                              boost::posix_time::seconds(3),
                              [&]()->bool { return vault_started_; })) {
        if (thd_.joinable())
          thd_.join();
      }
    }
    if (!vault_started_)
      return false;
    return true;
  }

  bool ClientController::StopVault(const maidsafe::asymm::PlainText& /*data*/,
                                   const maidsafe::asymm::Signature& /*signature*/,
                                   const maidsafe::asymm::Identity& /*identity*/) { return false; }
}  // namespace priv

}  // namespace maidsafe

