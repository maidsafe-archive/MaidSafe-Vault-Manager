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

namespace bai = boost::asio::ip;

namespace maidsafe {
namespace priv {



  ClientController::ClientController() : port_(5483),
                                         thd_(),
                                         asio_service_(new AsioService(3)),
                                         resolver_(asio_service_->service()),
                                         query_("", ""),
                                         endpoint_iterator_(),
                                         socket_(asio_service_->service()),
                                         mutex_(),
                                         cond_var_(),
                                         connected_to_manager_(false),
                                         vault_started_(false) {
                                           asio_service_->Start();
                                        }

  ClientController::~ClientController() {}


  void ClientController::ConnectToManager(uint16_t port) {
    std::string hello_string;
    Endpoint endpoint(boost::asio::ip::address_v4::loopback(), port);
    std::cout << "IN ConnectToManager: trying port " << port << std::endl;
    int message_type(static_cast<int>(VaultManagerMessageType::kHelloFromClient));
    maidsafe::priv::ClientHello hello;
    hello.set_hello("hello");
    std::shared_ptr<TcpTransport> transport;
    std::shared_ptr<MessageHandler> message_handler;
    ResetTransport(transport, message_handler);
    hello_string = message_handler->MakeSerialisedWrapperMessage(message_type,
                                                                hello.SerializeAsString());
    transport->Send(hello_string, endpoint, boost::posix_time::milliseconds(1000));
    std::cout << "ConnectToManager: sending hello to: " << endpoint.ip.to_string() << ", "
              << endpoint.port << std::endl;
  }

  void ClientController::ConnectToManagerCallback(const std::string& hello_response_string,
                                                  const Info& sender_info,
                                                  std::string* /*response*/) {
    std::cout << "IN ConnectToManagerCallback" << std::endl;
    {
    boost::mutex::scoped_lock lock(mutex_);
      ClientHelloResponse response;
      if (response.ParseFromString(hello_response_string)) {
        std::cout << "HELLO RESPONSE: " << response.hello_response() << std::endl;
        if (response.hello_response() == "hello response") {
          port_ = sender_info.endpoint.port;
          connected_to_manager_ = true;
          cond_var_.notify_all();
          return;
        }
      }
      if (!connected_to_manager_) {
        std::cout << "ConnectToManagerCallback: Couldn't parse response. Trying next port: "
                  << sender_info.endpoint.port + 1 << std::endl;
        ConnectToManager(sender_info.endpoint.port + 1);
      }
    }
    std::cout << "ConnectToManagerCallback: Successfully connected to manager." << std::endl;
  }

  void ClientController::HandleIncomingMessage(const int& type, const std::string& payload,
                                           const Info& info, std::string* response,
                                           std::shared_ptr<TcpTransport> /*transport*/,
                                           std::shared_ptr<MessageHandler> /*message_handler*/) {
    if (info.endpoint.ip.to_string() != "127.0.0.1") {
      std::cout << "HandleIncomingMessage: message is not of local origin." << std::endl;
      return;
    }
    VaultManagerMessageType message_type = boost::numeric_cast<VaultManagerMessageType>(type);
    switch (message_type) {
      case VaultManagerMessageType::kHelloResponseToClient:
        std::cout << "kHelloResponseToClient" << std::endl;
        ConnectToManagerCallback(payload, info, response);
        break;
      case VaultManagerMessageType::kStartResponseToClient:
        std::cout << "kStartResponseToClient" << std::endl;
        StartVaultRequestCallback(payload, info, response);
        break;
      default:
        std::cout << "Incorrect message type" << std::endl;
    }
  }

  void ClientController::OnConnectError(const TransportCondition &/*transport_condition*/,
                                        const Endpoint &remote_endpoint) {
    boost::mutex::scoped_lock lock(mutex_);
    if (!connected_to_manager_) {
      std::cout << "OnConnectError: Error sending or receiving connect message. Trying next port: "
                << remote_endpoint.port + 1 << std::endl;
      /*ConnectToManager(remote_endpoint.port + 1);*/
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
    int message_type(static_cast<int>(VaultManagerMessageType::kStartRequestFromClient));
    maidsafe::priv::ClientStartVaultRequest request;
    std::string keys_string;
    asymm::SerialiseKeys(keys, keys_string);
    std::cout << "StartVaultRequest: keys: " << EncodeToBase64(keys_string) << "length: "
              << keys_string.length() << std::endl;
    std::cout << "StartVaultRequest: identity: " << keys.identity << std::endl;
    request.set_keys(keys_string);
    request.set_account_name(account_name);
    std::string request_string;
    std::shared_ptr<TcpTransport> transport;
    std::shared_ptr<MessageHandler> message_handler;
    ResetTransport(transport, message_handler);
    request_string = message_handler->MakeSerialisedWrapperMessage(message_type,
                                                                  request.SerializeAsString());
    Endpoint endpoint(boost::asio::ip::address_v4::loopback(), port_);
    std::cout << "StartVaultRequest: Send: " << port_ << std::endl;
    transport->Send(request_string, endpoint, boost::posix_time::milliseconds(10000));
  }

  void ClientController::StartVaultRequestCallback(const std::string& start_response_string,
                                                   const Info& /*sender_info*/,
                                                   std::string* /*response*/) {
    {
      boost::mutex::scoped_lock lock(mutex_);
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

  void ClientController::ResetTransport(std::shared_ptr<TcpTransport>& transport,
                                        std::shared_ptr<MessageHandler>& message_handler ) {
    transport.reset(new TcpTransport(asio_service_->service()));
    message_handler.reset(new MessageHandler());
    transport->on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                          message_handler.get(), _1, _2, _3, _4));
    transport->on_error()->connect(boost::bind(&MessageHandler::OnError,
                                               message_handler.get(), _1, _2));
    message_handler->on_error()->connect(boost::bind(&ClientController::OnConnectError,
                                                     this, _1, _2));
    message_handler->SetCallback(
          boost::bind(&ClientController::HandleIncomingMessage, this, _1, _2, _3, _4, transport,
                      message_handler));
  }

  bool ClientController::StartVault(const maidsafe::asymm::Keys& keys,
                                    const std::string& account_name) {
    std::cout << "IN ClientController StartVault" << std::endl;
    try {
      thd_ = boost::thread([&] { ConnectToManager(port_); });  // NOLINT (Philip)
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
    if (!connected_to_manager_) {
      std::cout << "ClientController::StartVault: connection to manager failed" << std::endl;
      return false;
    }
    try {
      thd_ = boost::thread([&] { StartVaultRequest(keys, account_name); });  // NOLINT (Philip)
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

