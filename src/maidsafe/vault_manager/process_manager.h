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

#include <future>
#include <mutex>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/process/child.hpp"

#include "maidsafe/common/types.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

typedef uint64_t ProcessId;

// All functions provide the strong exception guarantee.
class ProcessManager {
 public:
  ProcessManager(boost::filesystem::path vault_executable_path, Port listening_port);
  ~ProcessManager();
  std::vector<VaultInfo> GetAll() const;
  void AddProcess(VaultInfo info);
  VaultInfo HandleVaultStarted(TcpConnectionPtr connection, ProcessId process_id);
  void AssignOwner(const NonEmptyString& label, const passport::PublicMaid::Name& owner_name,
                   DiskUsage max_disk_usage);
  // If the process doesn't exist, a default-constructed unique_ptr (i.e. null) is returned.
  std::unique_ptr<std::future<void>> StopProcess(TcpConnectionPtr connection);
  VaultInfo Find(const NonEmptyString& label) const;

 private:
  ProcessManager(const ProcessManager&) = delete;
  ProcessManager(ProcessManager&&) = delete;
  ProcessManager& operator=(ProcessManager) = delete;

  struct Child {
    Child();
    explicit Child(VaultInfo info);
    Child(Child&& other);
    Child& operator=(Child other);
    VaultInfo info;
    boost::process::child process;
    std::vector<std::string> process_args;
    bool stop_process;
  private:
    Child(const Child&) = delete;
  };
  friend void swap(Child& lhs, Child& rhs);

  void StartProcess(std::vector<Child>::iterator itr);
  std::future<void> StopProcess(Child& vault);

  std::vector<Child>::const_iterator DoFind(const NonEmptyString& label) const;
  std::vector<Child>::iterator DoFind(const NonEmptyString& label);
  ProcessId GetProcessId(const Child& vault) const;
  bool IsRunning(const Child& vault) const;

  const boost::filesystem::path kVaultExecutablePath_;
  const Port kListeningPort_;
  std::vector<Child> vaults_;
  mutable std::mutex mutex_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_PROCESS_MANAGER_H_
