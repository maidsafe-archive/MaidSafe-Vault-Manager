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

#ifndef MAIDSAFE_VAULT_MANAGER_VAULT_MANAGER_H_
#define MAIDSAFE_VAULT_MANAGER_VAULT_MANAGER_H_

#include <memory>
#include <string>

#include "asio/io_service_strand.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/config_file_handler.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

struct ChallengeResponse;
class ClientConnections;
struct LogMessage;
class NewConnections;
class ProcessManager;
struct StartVaultRequest;
struct TakeOwnershipRequest;
struct VaultStarted;

// The VaultManager has several responsibilities:
// * Reads config file on startup and restarts vaults listed in file.
// * Writes details of all vaults to config file.
// * Listens and responds to client and vault requests on the loopback address.
class VaultManager {
 public:
  VaultManager(const VaultManager&) = delete;
  VaultManager(VaultManager&&) = delete;
  VaultManager operator=(VaultManager) = delete;

  VaultManager();
  ~VaultManager();

  void TearDownWithInterval();

 private:
  void HandleNewConnection(tcp::ConnectionPtr connection);
  void HandleConnectionClosed(tcp::ConnectionPtr connection);
  void HandleReceivedMessage(tcp::ConnectionPtr connection, tcp::Message&& message);

  // Messages from Client
  void HandleValidateConnectionRequest(tcp::ConnectionPtr connection);
  void HandleChallengeResponse(tcp::ConnectionPtr connection,
                               ChallengeResponse&& challenge_response);
  void HandleStartVaultRequest(tcp::ConnectionPtr connection,
                               StartVaultRequest&& start_vault_request);
  void HandleTakeOwnershipRequest(tcp::ConnectionPtr connection,
                                  TakeOwnershipRequest&& take_ownership_request);
  void HandleSetNetworkAsStable();
  void HandleNetworkStableRequest(tcp::ConnectionPtr connection);

  // Messages from Vault
  void HandleVaultStarted(tcp::ConnectionPtr connection, VaultStarted&& vault_started);
  void HandleJoinedNetwork(tcp::ConnectionPtr connection);
  void HandleLogMessage(tcp::ConnectionPtr connection, LogMessage&& log_message);

  void RemoveFromNewConnections(tcp::ConnectionPtr connection);
  void ChangeChunkstorePath(VaultInfo vault_info);

  ConfigFileHandler config_file_handler_;
  bool network_stable_, tear_down_with_interval_;
  AsioService asio_service_;
  asio::io_service::strand strand_;
  std::shared_ptr<tcp::Listener> listener_;
  std::shared_ptr<ProcessManager> process_manager_;
  std::shared_ptr<ClientConnections> client_connections_;
  std::shared_ptr<NewConnections> new_connections_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_MANAGER_H_
