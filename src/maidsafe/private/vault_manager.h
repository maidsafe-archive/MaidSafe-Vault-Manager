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

#ifndef MAIDSAFE_PRIVATE_VAULT_MANAGER_H_
#define MAIDSAFE_PRIVATE_VAULT_MANAGER_H_

#include <condition_variable>
#include <mutex>
#include <cstdint>
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

#include "maidsafe/private/download_manager.h"
#include "maidsafe/private/process_manager.h"


namespace maidsafe {

namespace priv {

namespace protobuf { class VaultInfo; }

namespace detail { class Platform; }

class LocalTcpTransport;

enum class MessageType {
  kPing = 1,
  kStartVaultRequest,
  kStartVaultResponse,
  kVaultIdentityRequest,
  kVaultIdentityResponse,
  kVaultShutdownQuery,
  kVaultShutdownResponse
};

// The VaultManager has several responsibilities:
// * Reads config file on startup and restarts vaults listed in file as having been started before.
// * Writes details of all vaults to config file.
// * Listens and responds to client and vault requests on the loopback address.
// * Regularly checks for (and downloads) updated client or vault executables.
class VaultManager {
 public:
  explicit VaultManager(const std::string& parent_path);
  ~VaultManager();
  static std::string kConfigFileName() { return "config-global.dat"; }
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
                                                                                          //  uint16_t client_port;
    std::mutex mutex;
    std::condition_variable cond_var;
    bool requested_to_run;
    bool vault_requested;
  };

  VaultManager(const VaultManager&);
  VaultManager operator=(const VaultManager&);
  void RestartVaultManager(const std::string& latest_file,
                           const std::string& executable_name) const;

  // Config file handling
  bool EstablishConfigFilePath();
  bool ReadConfigFile();
  bool WriteConfigFile();

  // Client and vault request handling
  void ListenForMessages();
  void HandleRequest(const std::string& request, std::string& response);
  void HandlePing(const std::string& request, std::string& response);
  void HandleStartVaultRequest(const std::string& request, std::string& response);
  void HandleVaultIdentityRequest(const std::string& request, std::string& response);
  void HandleVaultShutdownQuery(const std::string& request, std::string& response);
  // Must be in range [kMinUpdateInterval, kMaxUpdateInterval]
  void HandleSetUpdateInterval(const std::string& request, std::string& response);
  void HandleGetUpdateInterval(const std::string& request, std::string& response);

  // Update handling
  std::string FindLatestLocalVersion(const std::string& application) const;
  void ListenForUpdates(const boost::system::error_code& ec);

  // General
  bool InTestMode() const;
  ProcessIndex GetProcessIndexFromAccountName(const std::string& account_name) const;
  ProcessIndex AddVaultToProcesses(const std::string& chunkstore_path,
                                   const uintmax_t& chunkstore_capacity,
                                   const std::string& bootstrap_endpoint);
  void RestartVault(const std::string& account_name);
  void StopVault(const std::string& account_name);
//  void EraseVault(const std::string& account_name);
//  int32_t ListVaults(bool select) const;
  static std::string kVaultName() { return "pd-vault"; }
  static std::string kVaultManagerName() { return "vault-manager"; }


  ProcessManager process_manager_;
  DownloadManager download_manager_;
  AsioService asio_service_;
  boost::posix_time::time_duration update_interval_;
  boost::asio::deadline_timer update_timer_;
  mutable std::mutex update_mutex_;
  std::shared_ptr<LocalTcpTransport> transport_;
  uint16_t local_port_;
  std::vector<std::unique_ptr<VaultInfo>> vault_infos_;
  mutable std::mutex vault_infos_mutex_;
  std::condition_variable cond_var_;
  bool stop_listening_for_updates_;
  bool shutdown_requested_;
  std::string parent_path_;
  boost::filesystem::path config_file_path_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_VAULT_MANAGER_H_
