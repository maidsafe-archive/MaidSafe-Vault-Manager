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

#ifndef MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_
#define MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_

#include <boost/asio.hpp>
#include <boost/thread.hpp>

#include <string>

#include "maidsafe/common/rsa.h"

#include "maidsafe/common/asio_service.h"

#include "maidsafe/private/message_handler.h"
#include "maidsafe/private/tcp_transport.h"

namespace maidsafe {

namespace priv {

class ClientController {
 public:
  ClientController();
  ~ClientController();

  // Blocking call to start a vault with the specified identity information and account name.
  bool StartVault(const maidsafe::asymm::Keys& keys, const std::string& account_name);

  // Blocking call to stop the vault with the specified identity. For authentication, provide data
  // signed wth the vault's private key.
  bool StopVault(const maidsafe::asymm::PlainText& data,
                 const maidsafe::asymm::Signature& signature,
                 const maidsafe::asymm::Identity& identity);

 private:
  void ConnectToManager(uint16_t port);
  void ConnectToManagerCallback(const std::string& hello_response_string, const Info& sender_info,
                                std::string* response);
  void OnConnectError(const TransportCondition &transport_condition,
                      const Endpoint &remote_endpoint);
  void OnStartVaultError(const TransportCondition &transport_condition,
                         const Endpoint &remote_endpoint);
  void StartVaultRequest(const maidsafe::asymm::Keys& keys, const std::string& account_name);
  void StartVaultRequestCallback(const std::string& hello_response_string, const Info& sender_info,
                                 std::string* response);
  void HandleIncomingMessage(const int& type, const std::string& payload, const Info& info,
                             std::string* response, std::shared_ptr<TcpTransport> transport,
                             std::shared_ptr<MessageHandler> message_handler);
  void ResetTransport(std::shared_ptr<TcpTransport>& transport,
                      std::shared_ptr<MessageHandler>& message_handler);

  uint16_t port_;
  boost::thread thd_;
  std::shared_ptr<maidsafe::AsioService> asio_service_;
  boost::asio::ip::tcp::resolver resolver_;
  boost::asio::ip::tcp::resolver::query query_;
  boost::asio::ip::tcp::resolver::iterator endpoint_iterator_;
  boost::asio::ip::tcp::socket socket_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  bool connected_to_manager_;
  bool vault_started_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_
