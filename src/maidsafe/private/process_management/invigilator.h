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

#ifndef MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_INVIGILATOR_H_
#define MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_INVIGILATOR_H_

#include <condition_variable>
#include <mutex>
#include <cstdint>
#include <functional>
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

#include "maidsafe/private/process_management/download_manager.h"
#include "maidsafe/private/process_management/process_manager.h"
#include "maidsafe/private/process_management/utils.h"
#include "maidsafe/private/process_management/vault_info_pb.h"

namespace maidsafe {

namespace priv {

namespace process_management {

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
  kVaultShutdownRequest,
  kVaultShutdownResponse,
  kVaultShutdownResponseAck,
  kUpdateIntervalRequest,
  kUpdateIntervalResponse,
  kNewVersionAvailable,
  kNewVersionAvailableAck
};

// The Invigilator has several responsibilities:
// * Reads config file on startup and restarts vaults listed in file as having been started before.
// * Writes details of all vaults to config file.
// * Listens and responds to client and vault requests on the loopback address.
// * Regularly checks for (and downloads) updated client or vault executables.
class Invigilator {
 public:
  Invigilator();
  ~Invigilator();
  static uint16_t kMinPort() { return 5483; }
  static uint16_t kMaxPort() { return 5582; }
                                    // TODO(Fraser#5#): 2012-08-12 - Confirm these intervals are appropriate
  static boost::posix_time::time_duration kMinUpdateInterval();  // 5 minutes
  static boost::posix_time::time_duration kMaxUpdateInterval();  // 1 week

 private:
  struct VaultInfo {
    VaultInfo();
    void ToProtobuf(protobuf::VaultInfo* pb_vault_info) const;
    void FromProtobuf(const protobuf::VaultInfo& pb_vault_info);
    ProcessIndex process_index;
    std::string account_name;
    asymm::Keys keys;
    std::string chunkstore_path;
    uintmax_t chunkstore_capacity;
    uint16_t vault_port;
    bool requested_to_run, joined_network;
  };
  typedef std::shared_ptr<VaultInfo> VaultInfoPtr;
  typedef std::function<void(bool)> VoidWithBoolFunction;
  typedef std::pair<std::string, uint16_t> EndPoint;

  Invigilator(const Invigilator&);
  Invigilator operator=(const Invigilator&);

  void RestartInvigilator(const std::string& latest_file,
                          const std::string& executable_name) const;

  // Config file handling
  bool CreateConfigFile();
  bool ReadConfigFileAndStartVaults();
  bool WriteConfigFile();

  // Client and vault request handling
  bool ListenForMessages();
  void HandleReceivedMessage(const std::string& message, uint16_t peer_port);
  void HandleClientRegistrationRequest(const std::string& request, std::string& response);
  void HandleStartVaultRequest(const std::string& request, std::string& response);
  void HandleVaultIdentityRequest(const std::string& request, std::string& response);
  void HandleVaultJoinedNetworkRequest(const std::string& request, std::string& response);
  void HandleStopVaultRequest(const std::string& request, std::string& response);

  // Must be in range [kMinUpdateInterval, kMaxUpdateInterval]
  void HandleUpdateIntervalRequest(const std::string& request, std::string& response);
  void SendVaultShutdownRequest(const std::string& identity);
  bool SetUpdateInterval(const boost::posix_time::time_duration& update_interval);
  boost::posix_time::time_duration GetUpdateInterval() const;

  // Update handling
  void CheckForUpdates(const boost::system::error_code& ec);
  void UpdateExecutor();

  // General
  bool InTestMode() const;
  std::vector<VaultInfoPtr>::iterator FindFromIdentity(const std::string& identity);
  std::vector<Invigilator::VaultInfoPtr>::iterator FindFromProcessIndex(ProcessIndex process_index);
  bool StartVaultProcess(VaultInfoPtr& vault_info);
  void RestartVault(const std::string& identity);
  void HandleVaultShutdownResponse(const std::string& message,
                                   const VoidWithBoolFunction& callback);  // NOLINT (Fraser)
  bool StopVault(const std::string& identity,
                 const std::string& data,
                 const std::string& signature,
                 bool permanent);
  void StopAllVaults();
//  void EraseVault(const std::string& identity);
//  int32_t ListVaults(bool select) const;
  bool ObtainBootstrapInformation(protobuf::InvigilatorConfig& config);
  bool ReadBootstrapEndpoints(protobuf::InvigilatorConfig& config,
                              std::vector<EndPoint>& endpoints);
  bool AddBootstrapEndPoint(const std::string& ip, const uint16_t& port);

  ProcessManager process_manager_;
  DownloadManager download_manager_;
  AsioService asio_service_;
  boost::posix_time::time_duration update_interval_;
  boost::asio::deadline_timer update_timer_;
  mutable std::mutex update_mutex_;
  std::shared_ptr<LocalTcpTransport> transport_;
  uint16_t local_port_;
  std::vector<VaultInfoPtr> vault_infos_;
  mutable std::mutex vault_infos_mutex_;
  std::vector<uint16_t> client_ports_;
  mutable std::mutex client_ports_mutex_;
  boost::filesystem::path config_file_path_;
};

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_INVIGILATOR_H_
