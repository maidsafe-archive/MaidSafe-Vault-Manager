/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
