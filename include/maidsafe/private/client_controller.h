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

#ifndef MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_
#define MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "boost/asio/ip/udp.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

struct Endpoint;
struct Info;
class TcpTransport;
class MessageHandler;

class ClientController {
 public:
  ClientController();
  ~ClientController();

  // Blocking call to start a vault with the specified identity information and account name.
  bool StartVault(const asymm::Keys& keys,
                  const std::string& account_name,
                  const boost::asio::ip::udp::endpoint& bootstrap_endpoint =
                      boost::asio::ip::udp::endpoint());

  // Blocking call to stop the vault with the specified identity. For authentication, provide data
  // signed wth the vault's private key.
  bool StopVault(const asymm::PlainText& data,
                 const asymm::Signature& signature,
                 const asymm::Identity& identity);

 private:
  ClientController(const ClientController&);
  ClientController& operator=(const ClientController&);
  void ConnectToManager();
  void ConnectToManagerCallback(const std::string& hello_response_string,
                                const Info& sender_info);
  void OnSendError(const int& transport_condition,
                   const Endpoint& remote_endpoint,
                   const std::function<void(bool)>& callback);  // NOLINT
  void StartVaultRequest(const asymm::Keys& keys,
                         const std::string& account_name,
                         const boost::asio::ip::udp::endpoint& bootstrap_endpoint,
                         const std::function<void(bool)>& callback);  // NOLINT
  void StartVaultRequestCallback(const std::string& hello_response_string,
                                 const Info& sender_info,
                                 const std::function<void(bool)>& callback);  // NOLINT
  void HandleIncomingMessage(const int& type,
                             const std::string& payload,
                             const Info& info,
                             std::shared_ptr<TcpTransport> transport,
                             std::shared_ptr<MessageHandler> message_handler,
                             const std::function<void(bool)>& callback);  // NOLINT
  void ResetTransport(std::shared_ptr<TcpTransport>& transport,
                      std::shared_ptr<MessageHandler>& message_handler,
                      const std::function<void(bool)>& callback);  // NOLINT

  uint16_t port_;
  AsioService asio_service_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  enum State { kInitialising, kVerified, kFailed } state_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_
