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
#include <future>
#include <memory>
#include <mutex>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/routing/bootstrap_file_operations.h"

#include "maidsafe/vault_manager/vault_config.h"

namespace maidsafe {

namespace vault_manager {

class TcpConnection;
class VaultInterface;

typedef uint16_t Port;

class VaultInterface {
 public:
  explicit VaultInterface(Port vault_manager_port);
  ~VaultInterface();

  VaultConfig GetConfiguration();

  // Doesn't throw.
  int WaitForExit();

  void SendBootstrapContactToVaultManager(const routing::BootstrapContact& contact);
  void SendJoined();

#ifdef TESTING
  void KillConnection();
  void SendInvalidMessage();
  void StopProcess();
#endif

 private:
  VaultInterface(const VaultInterface&) = delete;
  VaultInterface(VaultInterface&&) = delete;
  VaultInterface& operator=(VaultInterface) = delete;

  //void HandleVaultJoinedAck(const std::string& message, std::function<void()> callback);
  //void RequestVaultIdentity(Port listening_port);
  //void HandleVaultIdentityResponse(const std::string& message, std::mutex& mutex);
  //void HandleReceivedRequest(const std::string& message, Port peer_port);
  //void HandleVaultShutdownRequest(const std::string& request, std::string& response);
  //void HandleSendEndpointToVaultManagerResponse(
  //    const std::string& message, std::function<void(bool)> callback);
  //void HandleBootstrapResponse(const std::string& message,
  //                             std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints,
  //                             std::function<void(bool)> callback);
  void HandleReceivedMessage(const std::string& wrapped_message);
  void OnConnectionClosed();

  void HandleVaultStartedResponse(const std::string& message);
  void HandleVaultShutdownRequest();

  std::promise<int> exit_code_promise_;
  std::once_flag exit_code_flag_;
  Port vault_manager_port_;
  std::function<void(std::string)> on_vault_started_response_;
  std::unique_ptr<VaultConfig> vault_config_;
  AsioService asio_service_;
  std::shared_ptr<TcpConnection> tcp_connection_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_INTERFACE_H_
