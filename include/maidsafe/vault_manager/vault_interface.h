/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_VAULT_MANAGER_VAULT_INTERFACE_H_
#define MAIDSAFE_VAULT_MANAGER_VAULT_INTERFACE_H_

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

namespace vault_manager {

class LocalTcpTransport;

class VaultInterface {
 public:
  VaultInterface(const std::string& vault_manager_identifier,
                  std::function<void()> stop_callback);
  ~VaultInterface();

  bool GetIdentity(std::unique_ptr<passport::Pmid>& pmid,
                   std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints);
  void ConfirmJoin();
  bool SendEndpointToVaultManager(const boost::asio::ip::udp::endpoint& endpoint);
  bool GetBootstrapNodes(std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints);

 private:
  typedef std::shared_ptr<LocalTcpTransport> TransportPtr;
  VaultInterface(const VaultInterface&);
  VaultInterface& operator=(const VaultInterface&);
  void HandleVaultJoinedAck(const std::string& message, std::function<void()> callback);
  void RequestVaultIdentity(Port listening_port);
  void HandleVaultIdentityResponse(const std::string& message, std::mutex& mutex);
  void HandleReceivedRequest(const std::string& message, Port peer_port);
  void HandleVaultShutdownRequest(const std::string& request, std::string& response);
  void HandleSendEndpointToVaultManagerResponse(
      const std::string& message, std::function<void(bool)> callback);
  void HandleBootstrapResponse(const std::string& message,
                               std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints,
                               std::function<void(bool)> callback);
  uint32_t process_index_;
  Port vault_manager_port_, local_port_;
  std::unique_ptr<passport::Pmid> pmid_;
  std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints_;
  std::function<void()> stop_callback_;
  AsioService asio_service_;
  TransportPtr receiving_transport_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_INTERFACE_H_
