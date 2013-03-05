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

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_VAULT_CONTROLLER_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_VAULT_CONTROLLER_H_

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

#include "maidsafe/passport/types.h"


namespace maidsafe {

namespace lifestuff_manager {

class LocalTcpTransport;

class VaultController {
 public:
  explicit VaultController(const std::string& usr_id = "lifestuff");
  ~VaultController();

  bool Start(const std::string& lifestuff_manager_identifier, std::function<void()> stop_callback);
  bool GetIdentity(std::unique_ptr<passport::Pmid>& pmid,
                   std::vector<boost::asio::ip::udp::endpoint> &bootstrap_endpoints);
  void ConfirmJoin();
  bool SendEndpointToLifeStuffManager(const boost::asio::ip::udp::endpoint& endpoint);
  bool GetBootstrapNodes(std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints);

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
                                                    std::function<void(bool)> callback);  // NOLINT (Philip)
  void HandleBootstrapResponse(const std::string& message,
                               std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints,
                               std::function<void(bool)> callback);  // NOLINT (Philip)
  uint32_t process_index_;
  uint16_t lifestuff_manager_port_, local_port_;
  std::unique_ptr<passport::Pmid> pmid_;
  std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints_;
  std::function<void()> stop_callback_;
  bool setuid_succeeded_;
  AsioService asio_service_;
  TransportPtr receiving_transport_;
};

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_VAULT_CONTROLLER_H_
