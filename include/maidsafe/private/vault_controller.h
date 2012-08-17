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

#ifndef MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_
#define MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_

#include <condition_variable>
#include <mutex>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

class LocalTcpTransport;

class VaultController {
 public:
  VaultController();
  ~VaultController();

  bool Start(const std::string& vaults_manager_identifier, std::function<void()> stop_callback);
  bool GetIdentity(asymm::Keys* keys, std::string* account_name);
  void ConfirmJoin(bool joined);

 private:
  typedef std::shared_ptr<LocalTcpTransport> TransportPtr;
  VaultController(const VaultController&);
  VaultController& operator=(const VaultController&);
  void HandleVaultJoinedAck(const std::string& message, std::function<void()> callback);
  void RequestVaultIdentity();
  void HandleVaultIdentityResponse(const std::string& message,
                                   std::mutex& mutex,
                                   std::condition_variable& cond_var);
  void HandleReceivedRequest(const std::string& message, uint16_t peer_port);
  void HandleVaultShutdownRequest(const std::string& request, std::string& response);
  void HandleVaultShutdownResponseAck(const std::string& request, std::string& response);
  uint32_t process_index_;
  uint16_t vaults_manager_port_;
  AsioService asio_service_;
  TransportPtr receiving_transport_;
  asymm::Keys keys_;
  std::string account_name_;
  bool shutdown_requested_;
  std::function<void()> stop_callback_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_
