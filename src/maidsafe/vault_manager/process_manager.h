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

#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "asio/io_service.hpp"
#ifdef MAIDSAFE_WIN32
#include "asio/windows/object_handle.hpp"
#else
#include "asio/signal_set.hpp"
#endif
#include "boost/filesystem/path.hpp"
#include "boost/process/child.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/tcp/connection.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

typedef uint64_t ProcessId;

enum class ProcessStatus { kBeforeStarted, kStarting, kRunning, kStopping };

// All functions provide the strong exception guarantee.
class ProcessManager {
 public:
  typedef std::function<void(maidsafe_error, int)> OnExitFunctor;

  ProcessManager(const ProcessManager&) = delete;
  ProcessManager(ProcessManager&&) = delete;
  ProcessManager& operator=(ProcessManager) = delete;

  static std::shared_ptr<ProcessManager> MakeShared(asio::io_service& io_service,
                                                    boost::filesystem::path vault_executable_path,
                                                    tcp::Port listening_port);
  ~ProcessManager();
  void StopAll();
  void StopAllWithInterval();
  std::vector<VaultInfo> GetAll() const;
  void AddProcess(VaultInfo info, int restart_count = 0);
  VaultInfo HandleVaultStarted(tcp::ConnectionPtr connection, ProcessId process_id);
  void AssignOwner(const NonEmptyString& label, const passport::PublicMaid::Name& owner_name,
                   DiskUsage max_disk_usage);
  void StopProcess(tcp::ConnectionPtr connection, OnExitFunctor on_exit_functor = nullptr);
  // Returns false if the process doesn't exist.
  bool HandleConnectionClosed(tcp::ConnectionPtr connection);
  VaultInfo Find(const NonEmptyString& label) const;
  VaultInfo Find(tcp::ConnectionPtr connection) const;

 private:
  ProcessManager(asio::io_service &io_service, boost::filesystem::path vault_executable_path,
                 tcp::Port listening_port);

  struct Child {
    Child(VaultInfo info, asio::io_service &io_service, int restarts);
    Child(Child&& other);
    Child& operator=(Child other);
    VaultInfo info;
    OnExitFunctor on_exit;
    std::unique_ptr<Timer> timer;
    int restart_count;
    std::vector<std::string> process_args;
    ProcessStatus status;
#ifdef MAIDSAFE_WIN32
    asio::windows::object_handle handle;
#endif
    boost::process::child process;
   private:
    Child(const Child&) = delete;
  };
  friend void swap(Child& lhs, Child& rhs);

  void StartProcess(std::vector<Child>::iterator itr);
  void InitSignalHandler();

  std::vector<Child>::const_iterator DoFind(const NonEmptyString& label) const;
  std::vector<Child>::iterator DoFind(const NonEmptyString& label);
  std::vector<Child>::const_iterator DoFind(tcp::ConnectionPtr connection) const;
  std::vector<Child>::iterator DoFind(tcp::ConnectionPtr connection);
  ProcessId GetProcessId(const Child& vault) const;
  bool IsRunning(const Child& vault) const;
  void OnProcessExit(const NonEmptyString& label, int exit_code, bool terminate = false);
  void TerminateProcess(std::vector<Child>::iterator itr);
  void InvokeOnExitFunctor(OnExitFunctor on_exit, int exit_code, bool terminate);
  void RestartIfRequired(int restart_count, VaultInfo vault_info);

  asio::io_service &io_service_;
#ifndef MAIDSAFE_WIN32
  asio::signal_set signal_set_;
#endif
  std::once_flag stop_all_flag_;
  const tcp::Port kListeningPort_;
  const boost::filesystem::path kVaultExecutablePath_;
  std::vector<Child> vaults_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_PROCESS_MANAGER_H_
