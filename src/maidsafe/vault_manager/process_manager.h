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
#include "maidsafe/common/types.h"
#include "maidsafe/passport/types.h"
#include "maidsafe/routing/bootstrap_file_operations.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

typedef uint64_t ProcessId;

namespace protobuf { class VaultManagerConfig; }
struct VaultInfo;

class ProcessManager {
 public:
  ProcessManager();
  ~ProcessManager();
  void AddVaultsDetailsToConfig(const crypto::AES256Key& symm_key,
                                const crypto::AES256InitialisationVector& symm_iv,
                                protobuf::VaultManagerConfig& config) const;
  // Provides strong exception guarantee.
  void AddProcess(VaultInfo vault_info);
  // Provides strong exception guarantee.  Returns the owner name, which could be uninitialised if
  // the vault is unowned.
  passport::PublicMaid::Name HandleNewConnection(TcpConnectionPtr connection, ProcessId process_id,
      crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
      const routing::BootstrapContacts& bootstrap_contacts);
  // Provides strong exception guarantee.  Restarts vault if 'vault_info.chunkstore_path' is
  // different from current one.
  void AssignOwner(TcpConnectionPtr client_connection, VaultInfo vault_info);
  bool HandleConnectionClosed(TcpConnectionPtr connection);

 private:
  ProcessManager(const ProcessManager&) = delete;
  ProcessManager(ProcessManager&&) = delete;
  ProcessManager& operator=(ProcessManager) = delete;

  void StartProcess(std::vector<VaultInfo>::iterator itr);
  std::future<void> StopProcess(VaultInfo& vault_info);

  ProcessId GetProcessId(const boost::process::child& child) const;

  std::vector<VaultInfo> vaults_;
  mutable std::mutex mutex_;
  std::condition_variable cond_var_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_PROCESS_MANAGER_H_
