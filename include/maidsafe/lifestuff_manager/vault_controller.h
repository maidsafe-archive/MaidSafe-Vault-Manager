/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
  VaultController(const std::string& lifestuff_manager_identifier,
                  std::function<void()> stop_callback);
  ~VaultController();

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
  void RequestVaultIdentity(uint16_t listening_port);
  void HandleVaultIdentityResponse(const std::string& message, std::mutex& mutex);
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
  AsioService asio_service_;
  TransportPtr receiving_transport_;
};

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_VAULT_CONTROLLER_H_
