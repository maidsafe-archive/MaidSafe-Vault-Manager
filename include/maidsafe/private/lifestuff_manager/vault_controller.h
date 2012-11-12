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

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_VAULT_CONTROLLER_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_VAULT_CONTROLLER_H_

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "boost/asio.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/utils/fob.h"


namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

class LocalTcpTransport;

class VaultController {
 public:
  explicit VaultController(const std::string& usr_id = "lifestuff");

  bool Start(const std::string& lifestuff_manager_identifier, std::function<void()> stop_callback);
  bool GetIdentity(Fob& fob,
                   std::string& account_name,
                   std::vector<std::pair<std::string, uint16_t>> &bootstrap_endpoints);
  void ConfirmJoin(bool joined);
  bool SendEndpointToLifeStuffManager(const std::pair<std::string, uint16_t>& endpoint);
  bool GetBootstrapNodes(std::vector<std::pair<std::string, uint16_t> >& bootstrap_endpoints);

 private:
  typedef std::shared_ptr<LocalTcpTransport> TransportPtr;
  VaultController(const VaultController&);
  VaultController& operator=(const VaultController&);
  void HandleVaultJoinedAck(const std::string& message, std::function<void()> callback);
  bool RequestVaultIdentity(uint16_t listening_port);
  bool HandleVaultIdentityResponse(const std::string& message, std::mutex& mutex);
  void HandleReceivedRequest(const std::string& message, uint16_t peer_port);
  void HandleVaultShutdownRequest(const std::string& request, std::string& response);
  void HandleSendEndpointToLifeStuffManagerResponse(const std::string& message,
                                               std::function<void(bool)> callback);  //NOLINT (Philip)
  void HandleBootstrapResponse(const std::string& message,
                               std::vector<std::pair<std::string, uint16_t> > &bootstrap_endpoints,
                               std::function<void(bool)> callback);  //NOLINT (Philip)
  uint32_t process_index_;
  uint16_t lifestuff_manager_port_, local_port_;
  Fob fob_;
  std::string account_name_;
  std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints_;
  std::function<void()> stop_callback_;
  bool setuid_succeeded_;
  AsioService asio_service_;
  TransportPtr receiving_transport_;
};

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_VAULT_CONTROLLER_H_
