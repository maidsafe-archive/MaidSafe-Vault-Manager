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

#include <string>
#include <vector>
#include <utility>

#include "maidsafe/common/asio_service.h"

#include "maidsafe/private/process_manager.h"
#include "maidsafe/private/download_manager.h"
#include "boost/filesystem/fstream.hpp"
#include "boost/filesystem/operations.hpp"

#include "maidsafe/private/tcp_transport.h"
#include "maidsafe/private/message_handler.h"

namespace maidsafe {

namespace priv {

enum class VaultManagerMessageType {
  kHelloFromClient = 1,
  kHelloResponseToClient = 2,
  kStartRequestFromClient = 3,
  kStartResponseToClient = 4,
  kIdentityInfoRequestFromVault = 5,
  kIdentityInfoToVault = 6,
  kShutdownRequestFromVault = 7,
  kShutdownResponseToVault = 8
};

struct WaitingVaultInfo {
  WaitingVaultInfo() : vault_vmid(), client_endpoint(), account_name(), keys(), chunkstore_path(),
                       chunkstore_capacity(), mutex_(), cond_var_(), vault_requested_(false) {}
  std::string vault_vmid;
  Endpoint client_endpoint;
  std::string account_name;
  asymm::Keys keys;
  std::string chunkstore_path;
  std::string chunkstore_capacity;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  bool vault_requested_;
};

class VaultManager {
 public:
  static const uint16_t kMinPort, kMaxPort;

  explicit VaultManager(const std::string &parent_path = "");
  ~VaultManager();

  std::string RunVault(std::string chunkstore_path, std::string chunkstore_capacity,
                       std::string bootstrap_endpoint = "");
  void StartListening();
  void StopListening();
  bool ReadConfig();
  void StopVault(int32_t id);
  void EraseVault(int32_t id);
  int32_t ListVaults(bool select);
  void RestartVault(std::string id);
  void RestartVaultManager(std::string latest_file, std::string executable_name);
  int32_t get_process_vector_size();
  void ListenForUpdates();
  void ListenForMessages();
  void HandleClientHello(const std::string& hello_string, const Info& info, std::string* response);
  void HandleClientStartVaultRequest(const std::string& start_vault_string, const Info& info,
                                     std::string* response);
  void HandleVaultInfoRequest(const std::string& vault_info_string, const Info& info,
                              std::string* response);
  void HandleVaultShutdownRequest(const std::string& vault_shutdown_string, const Info& info,
                              std::string* response);
  void HandleIncomingMessage(const int& type, const std::string& payload, const Info& info,
                             std::string* response);
  void OnError(const TransportCondition &transport_condition, const Endpoint &remote_endpoint);
  std::pair<std::string, std::string> FindLatestLocalVersion(std::string name,
                                                             std::string platform,
                                                             std::string cpu_size);
  void ProcessStopHandler();

 private:
//   It should be decided if the following three methods are going to be private or public
//   void RunVault(/*std::string chunkstore_path, */std::string chunkstore_capacity,
//                     bool new_vault);
//   void StopVault();
//   bool ReadConfig();
  explicit VaultManager(const maidsafe::priv::VaultManager&);
  VaultManager operator=(const maidsafe::priv::VaultManager&);

  bool WriteConfig();
  std::vector<std::string> vmid_vector_;
  std::vector<maidsafe::Process> process_vector_;
  ProcessManager manager_;
  DownloadManager download_manager_;
  std::shared_ptr<AsioService> asio_service_;
  priv::MessageHandler msg_handler_;
  std::shared_ptr<TcpTransport> transport_;
  uint16_t local_port_;
  std::vector<std::shared_ptr<WaitingVaultInfo>> client_started_vault_vmids_;
  std::vector<std::shared_ptr<WaitingVaultInfo>> config_file_vault_vmids_;
  boost::thread mediator_thread_;
  boost::thread updates_thread_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  bool stop_listening_for_messages_;
  bool stop_listening_for_updates_;
  bool shutdown_requested_;
  uint16_t stopped_vaults_;
  std::string parent_path_;
};

}  // namespace private

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_VAULT_MANAGER_H_
