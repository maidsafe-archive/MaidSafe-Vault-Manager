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

#include <condition_variable>
#include <mutex>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

class LocalTcpTransport;

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
  typedef std::shared_ptr<LocalTcpTransport> TransportPtr;
  ClientController(const ClientController&);
  ClientController& operator=(const ClientController&);
  void PingVaultManager();
  void HandlePingResponse(const std::string& message, TransportPtr transport);
  void StartVaultRequest(const std::string& account_name,
                         const asymm::Keys& keys,
                         const boost::asio::ip::udp::endpoint& bootstrap_endpoint,
                         const std::function<void(bool)>& callback);  // NOLINT
  void HandleStartVaultResponse(const std::string& message,
                                TransportPtr transport,
                                const std::function<void(bool)>& callback);  // NOLINT

  uint16_t vault_manager_port_;
  AsioService asio_service_;
  std::mutex mutex_;
  std::condition_variable cond_var_;
  enum State { kInitialising, kVerified, kFailed } state_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_
