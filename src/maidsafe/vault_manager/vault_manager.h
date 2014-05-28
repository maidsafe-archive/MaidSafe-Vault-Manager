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

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/config_file_handler.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

class TcpListener;
class ClientConnections;
class NewConnections;
class ProcessManager;

// The VaultManager has several responsibilities:
// * Reads config file on startup and restarts vaults listed in file.
// * Writes details of all vaults to config file.
// * Listens and responds to client and vault requests on the loopback address.
// * Maintains the bootstrap list (peer contacts known to its vault(s)).
class VaultManager {
 public:
  VaultManager();
  ~VaultManager();

 private:
  VaultManager(const VaultManager&) = delete;
  VaultManager(VaultManager&&) = delete;
  VaultManager operator=(VaultManager) = delete;

  void HandleNewConnection(TcpConnectionPtr connection);
  void HandleConnectionClosed(TcpConnectionPtr connection);
  void HandleReceivedMessage(TcpConnectionPtr connection, const std::string& wrapped_message);

  // Messages from Client
  void HandleValidateConnectionRequest(TcpConnectionPtr connection);
  void HandleChallengeResponse(TcpConnectionPtr connection, const std::string& message);
  void HandleStartVaultRequest(TcpConnectionPtr connection, const std::string& message);
  void HandleTakeOwnershipRequest(TcpConnectionPtr connection, const std::string& message);
  void HandleBootstrapContactsRequest(TcpConnectionPtr connection);

  // Messages from Vault
  void HandleVaultStarted(TcpConnectionPtr connection, const std::string& message);
  void HandleJoinedNetwork(TcpConnectionPtr connection);
  void HandleLogMessage(TcpConnectionPtr connection, const std::string& message);

  void RemoveFromNewConnections(TcpConnectionPtr connection);
  void ChangeChunkstorePath(VaultInfo vault_info);

  const boost::filesystem::path kBootstrapFilePath_;
  ConfigFileHandler config_file_handler_;
  AsioService asio_service_;
  std::shared_ptr<TcpListener> listener_;
  std::shared_ptr<ProcessManager> process_manager_;
  std::shared_ptr<ClientConnections> client_connections_;
  std::shared_ptr<NewConnections> new_connections_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_MANAGER_H_
