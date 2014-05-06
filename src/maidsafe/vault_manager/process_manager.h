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

#ifndef MAIDSAFE_VAULT_MANAGER_PROCESS_MANAGER_H_
#define MAIDSAFE_VAULT_MANAGER_PROCESS_MANAGER_H_

#include <condition_variable>
#include <future>
#include <mutex>
#include <vector>

#include "boost/process/child.hpp"

#include "maidsafe/common/crypto.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

namespace protobuf { class VaultManagerConfig; }
struct VaultInfo;

class ProcessManager {
 public:
  ProcessManager();
  ~ProcessManager();
  void WriteToConfigFile(const crypto::AES256Key& symm_key,
                         const crypto::AES256InitialisationVector& symm_iv,
                         protobuf::VaultManagerConfig& config) const;
  void AddProcess(VaultInfo vault_info);
  void HandleNewConnection(TcpConnectionPtr connection);
  void HandleConnectionClosed(TcpConnectionPtr connection);

 private:
  ProcessManager(const ProcessManager&) = delete;
  ProcessManager& operator=(ProcessManager) = delete;

  void StartProcess(std::vector<VaultInfo>::iterator itr);
  std::future<void> StopProcess(VaultInfo& vault_info);

  std::vector<VaultInfo> vaults_;
  mutable std::mutex mutex_;
  std::condition_variable cond_var_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_PROCESS_MANAGER_H_
