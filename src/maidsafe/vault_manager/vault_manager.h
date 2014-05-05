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

//#include <condition_variable>
//#include <mutex>
//#include <cstdint>
//#include <functional>
//#include <map>
#include <memory>
//#include <string>
//#include <utility>
//#include <vector>
//
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/crypto.h"

#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/process_manager.h"
#include "maidsafe/vault_manager/tcp_listener.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

namespace protobuf { class VaultManagerConfig; }

class TcpConnection;

// The VaultManager has several responsibilities:
// * Reads config file on startup and restarts vaults listed in file.
// * Writes details of all vaults to config file.
// * Listens and responds to client and vault requests on the loopback address.
// * Maintains the bootstrap list (peer contacts known to its vault(s)).
class VaultManager {
 public:
  explicit VaultManager();
  ~VaultManager();

 private:
  VaultManager(const VaultManager&) = delete;
  VaultManager(VaultManager&&) = delete;
  VaultManager operator=(VaultManager) = delete;

  // Config file handling
  void CreateConfigFile();
  void ReadConfigFileAndStartVaults();
  void WriteConfigFile() const;

  // Client and vault request handling
  void HandleNewConnection(TcpConnectionPtr connection);

  // General
  void StartVaultProcess(VaultInfo vault_info);




  // Client and vault request handling
  void HandleReceivedMessage(const std::string& message, Port peer_port);
  void HandleClientRegistrationRequest(const std::string& request, std::string& response);
  void HandleStartVaultRequest(const std::string& request, std::string& response);
  void HandleVaultIdentityRequest(const std::string& request, std::string& response);
  void HandleVaultJoinedNetworkRequest(const std::string& request, std::string& response);
  void HandleStopVaultRequest(const std::string& request, std::string& response);
  void HandleSendEndpointToVaultManagerRequest(const std::string& request,
                                                   std::string& response);
  void HandleBootstrapRequest(const std::string& request, std::string& response);

  // Requests to vault
  void SendVaultShutdownRequest(const Identity& identity);

  // Requests to client
  // NOTE: vault_info_mutex_ must be locked when calling this function.
  void SendVaultJoinConfirmation(const passport::Pmid::Name& pmid_name, bool join_result);
  void SendNewVersionAvailable(Port client_port);

  // Response handling from client
  void HandleVaultJoinConfirmationAck(const std::string& message,
                                      std::function<void(bool)> callback);
  void HandleNewVersionAvailableAck(const std::string& message,
                                    std::function<void(bool)> callback);

  // General
  bool InTestMode() const;
  void RestartVault(const passport::Pmid::Name& pmid_name);
  bool StopVault(const passport::Pmid::Name& pmid_name, const asymm::PlainText& data,
                 const asymm::Signature& signature, bool permanent);
  void StopAllVaults();
  //bool ObtainBootstrapInformation(protobuf::VaultManagerConfig& config);
  //void LoadBootstrapEndpoints(const protobuf::Bootstrap& end_points);
  //bool AddBootstrapEndPoint(const std::string& ip, Port port);
  //bool AmendVaultDetailsInConfigFile(const VaultInfoPtr& vault_info, bool existing_vault);

  crypto::AES256Key symm_key_;
  crypto::AES256InitialisationVector symm_iv_;
  boost::filesystem::path config_file_path_, vault_executable_path_;
  AsioService asio_service_;
  TcpListener listener_;
  ProcessManager process_manager_;
  TcpConnectionPtr client_connection_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_MANAGER_H_
