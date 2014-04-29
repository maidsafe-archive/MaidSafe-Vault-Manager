/*  Copyright 2012 MaidSafe.net limited

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
//#include <memory>
//#include <string>
//#include <utility>
//#include <vector>
//
//#include "boost/asio/deadline_timer.hpp"
//#include "boost/filesystem/path.hpp"
//#include "boost/thread/condition_variable.hpp"
//#include "boost/thread/mutex.hpp"
//#include "boost/thread/thread.hpp"
//
//#include "maidsafe/common/asio_service.h"
//#include "maidsafe/common/rsa.h"
#include "maidsafe/common/crypto.h"
//
//#include "maidsafe/passport/types.h"
//
#include "maidsafe/vault_manager/config.h"
//#include "maidsafe/vault_manager/utils.h"

namespace maidsafe {

namespace vault_manager {

class LocalTcpTransport;

// The VaultManager has several responsibilities:
// * Reads config file on startup and restarts vaults listed in file as having been started before.
// * Writes details of all vaults to config file.
// * Listens and responds to client and vault requests on the loopback address.
class VaultManager {
 public:
  VaultManager();
  ~VaultManager();

 private:
                                                                    typedef std::pair<std::string, Port> EndPoint;

  VaultManager(const VaultManager&) = delete;
  VaultManager(VaultManager&&) = delete;
  VaultManager operator=(VaultManager) = delete;

  void Initialise();

  // Config file handling
  bool CreateConfigFile();
  bool ReadConfigFileAndStartVaults();
  bool WriteConfigFile();
  bool ReadFileToVaultManagerConfig(const boost::filesystem::path& file_path,
                                    protobuf::VaultManagerConfig& config);

  // Client and vault request handling
  bool ListenForMessages();
  void HandleReceivedMessage(const std::string& message, Port peer_port);
  void HandleClientRegistrationRequest(const std::string& request, std::string& response);
  void HandleStartVaultRequest(const std::string& request, std::string& response);
  void HandleVaultIdentityRequest(const std::string& request, std::string& response);
  void HandleVaultJoinedNetworkRequest(const std::string& request, std::string& response);
  void HandleStopVaultRequest(const std::string& request, std::string& response);
  void HandleSendEndpointToVaultManagerRequest(const std::string& request,
                                                   std::string& response);
  void HandleBootstrapRequest(const std::string& request, std::string& response);

  // Must be in range [kMinUpdateInterval, kMaxUpdateInterval]
  void HandleUpdateIntervalRequest(const std::string& request, std::string& response);
  bool SetUpdateInterval(const boost::posix_time::time_duration& update_interval);
  boost::posix_time::time_duration GetUpdateInterval() const;

  // Requests to vault
  void SendVaultShutdownRequest(const Identity& identity);

  // Requests to client
  // NOTE: vault_info_mutex_ must be locked when calling this function.
  void SendVaultJoinConfirmation(const passport::Pmid::Name& pmid_name, bool join_result);
  void SendNewVersionAvailable(Port client_port);

  // Response handling from client
  void HandleVaultJoinConfirmationAck(const std::string& message,
                                      std::function<void(bool)> callback);  // NOLINT (Philip)
  void HandleNewVersionAvailableAck(const std::string& message,
                                    std::function<void(bool)> callback);  // NOLINT (Philip)

  // Update handling
  void CheckForUpdates(const boost::system::error_code& ec);
  bool IsInstaller(const boost::filesystem::path& path);
  void UpdateExecutor();

  // General
  bool InTestMode() const;
  std::vector<VaultInfoPtr>::iterator FindFromPmidName(const passport::Pmid::Name& pmid_name);
  std::vector<VaultManager::VaultInfoPtr>::iterator FindFromProcessIndex(
      ProcessIndex process_index);
  bool StartVaultProcess(VaultInfoPtr& vault_info);
  void RestartVault(const passport::Pmid::Name& pmid_name);
  bool StopVault(const passport::Pmid::Name& pmid_name, const asymm::PlainText& data,
                 const asymm::Signature& signature, bool permanent);
  void StopAllVaults();
  //  void EraseVault(const std::string& identity);
  //  int32_t ListVaults(bool select) const;
  bool ObtainBootstrapInformation(protobuf::VaultManagerConfig& config);
  void LoadBootstrapEndpoints(const protobuf::Bootstrap& end_points);
  bool AddBootstrapEndPoint(const std::string& ip, Port port);
  bool AmendVaultDetailsInConfigFile(const VaultInfoPtr& vault_info, bool existing_vault);

  crypto::AES256Key symm_key_;
  crypto::AES256InitialisationVector symm_iv_;





  ProcessManager process_manager_;
  Port local_port_;
  boost::filesystem::path config_file_path_;
  std::vector<VaultInfoPtr> vault_infos_;
  mutable std::mutex vault_infos_mutex_;
  std::map<Port, int> client_ports_and_versions_;
  mutable std::mutex client_ports_mutex_;
  std::vector<EndPoint> endpoints_;
  std::mutex config_file_mutex_;
  bool need_to_stop_;
  AsioService asio_service_;
  std::shared_ptr<LocalTcpTransport> transport_;
  passport::Maid maid_;
  SafeReadOnlySharedMemory initial_contact_memory_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_MANAGER_H_
