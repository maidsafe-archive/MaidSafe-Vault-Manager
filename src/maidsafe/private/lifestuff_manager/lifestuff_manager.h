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

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_LIFESTUFF_MANAGER_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_LIFESTUFF_MANAGER_H_

#include <condition_variable>
#include <mutex>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "boost/asio/deadline_timer.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/data_types/fob.h"

#include "maidsafe/private/lifestuff_manager/download_manager.h"
#include "maidsafe/private/lifestuff_manager/process_manager.h"
#include "maidsafe/private/lifestuff_manager/utils.h"
#include "maidsafe/private/lifestuff_manager/vault_info_pb.h"

namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace detail { class Platform; }

class LocalTcpTransport;

enum class MessageType {
  kClientRegistrationRequest = 1,
  kClientRegistrationResponse,
  kStartVaultRequest,
  kStartVaultResponse,
  kStopVaultRequest,
  kStopVaultResponse,
  kVaultIdentityRequest,
  kVaultIdentityResponse,
  kVaultJoinedNetwork,
  kVaultJoinedNetworkAck,
  kVaultJoinConfirmation,
  kVaultJoinConfirmationAck,
  kVaultShutdownRequest,
  kVaultShutdownResponse,
  kVaultShutdownResponseAck,
  kSendEndpointToLifeStuffManagerRequest,
  kSendEndpointToLifeStuffManagerResponse,
  kUpdateIntervalRequest,
  kUpdateIntervalResponse,
  kNewVersionAvailable,
  kNewVersionAvailableAck,
  kBootstrapRequest,
  kBootstrapResponse
};

// The LifeStuffManager has several responsibilities:
// * Reads config file on startup and restarts vaults listed in file as having been started before.
// * Writes details of all vaults to config file.
// * Listens and responds to client and vault requests on the loopback address.
// * Regularly checks for (and downloads) updated client or vault executables.
class LifeStuffManager {
 public:
  LifeStuffManager();
  ~LifeStuffManager();
  static uint16_t kDefaultPort() { return 5483; }
  static uint16_t kMaxRangeAboveDefaultPort() { return 10; }

  // TODO(Fraser#5#): 2012-08-12 - Confirm these intervals are appropriate
  static boost::posix_time::time_duration kMinUpdateInterval() {
    return boost::posix_time::minutes(5);
  }
  static boost::posix_time::time_duration kMaxUpdateInterval() {
    return boost::posix_time::hours(24 * 7);
  }

 private:
  typedef std::shared_ptr<LocalTcpTransport> TransportPtr;
  struct VaultInfo {
    VaultInfo();
    void ToProtobuf(protobuf::VaultInfo* pb_vault_info) const;
    void FromProtobuf(const protobuf::VaultInfo& pb_vault_info);
    ProcessIndex process_index;
    std::string account_name;
    Fob fob;
    std::string chunkstore_path;
    uint16_t vault_port, client_port;
    bool requested_to_run, joined_network;
    int vault_version;
  };
  typedef std::shared_ptr<VaultInfo> VaultInfoPtr;
  typedef std::pair<std::string, uint16_t> EndPoint;

  LifeStuffManager(const LifeStuffManager&);
  LifeStuffManager operator=(const LifeStuffManager&);

  void Initialise();
  void RestartLifeStuffManager(const std::string& latest_file,
                               const std::string& executable_name) const;

  // Config file handling
  bool CreateConfigFile();
  bool ReadConfigFileAndStartVaults();
  bool WriteConfigFile();
  bool ReadFileToLifeStuffManagerConfig(const boost::filesystem::path& file_path,
                                        protobuf::LifeStuffManagerConfig& config);

  // Client and vault request handling
  bool ListenForMessages();
  void HandleReceivedMessage(const std::string& message, uint16_t peer_port);
  void HandleClientRegistrationRequest(const std::string& request, std::string& response);
  void HandleStartVaultRequest(const std::string& request, std::string& response);
  void HandleVaultIdentityRequest(const std::string& request, std::string& response);
  void HandleVaultJoinedNetworkRequest(const std::string& request, std::string& response);
  void HandleStopVaultRequest(const std::string& request, std::string& response);
  void HandleSendEndpointToLifeStuffManagerRequest(const std::string& request,
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
  void SendVaultJoinConfirmation(const Identity& identity, bool join_result);
  void SendNewVersionAvailable(uint16_t client_port);

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
  std::vector<VaultInfoPtr>::iterator FindFromIdentity(const Identity& identity);
  std::vector<LifeStuffManager::VaultInfoPtr>::iterator FindFromProcessIndex(
      ProcessIndex process_index);
  bool StartVaultProcess(VaultInfoPtr& vault_info);
  void RestartVault(const Identity& identity);
  bool StopVault(const Identity& identity,
                 const asymm::PlainText& data,
                 const asymm::Signature& signature,
                 bool permanent);
  void StopAllVaults();
//  void EraseVault(const std::string& identity);
//  int32_t ListVaults(bool select) const;
  bool ObtainBootstrapInformation(protobuf::LifeStuffManagerConfig& config);
  void LoadBootstrapEndpoints(const protobuf::Bootstrap& end_points);
  bool AddBootstrapEndPoint(const std::string& ip, const uint16_t& port);
  bool AmendVaultDetailsInConfigFile(const VaultInfoPtr& vault_info, bool existing_vault);

  ProcessManager process_manager_;
  DownloadManager download_manager_;
  uint16_t local_port_;
  boost::filesystem::path config_file_path_, latest_local_installer_path_;
  std::vector<VaultInfoPtr> vault_infos_;
  mutable std::mutex vault_infos_mutex_;
  std::map<uint16_t, int> client_ports_and_versions_;
  mutable std::mutex client_ports_mutex_;
  std::vector<EndPoint> endpoints_;
  std::mutex config_file_mutex_;
  bool need_to_stop_;
  AsioService asio_service_;
  boost::posix_time::time_duration update_interval_;
  mutable std::mutex update_mutex_;
  boost::asio::deadline_timer update_timer_;
  std::shared_ptr<LocalTcpTransport> transport_;
};

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_LIFESTUFF_MANAGER_H_
