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

#include "maidsafe/vault_manager/process_manager.h"

#include <algorithm>
#include <type_traits>

#include "boost/process/execute.hpp"
#include "boost/process/initializers.hpp"
#include "boost/process/mitigate.hpp"
#include "boost/process/terminate.hpp"
#include "boost/process/wait_for_exit.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/process.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/tcp_connection.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.pb.h"

namespace bp = boost::process;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace {

bool ConnectionsEqual(const TcpConnectionPtr& lhs, const TcpConnectionPtr& rhs) {
  return !lhs.owner_before(rhs) && !rhs.owner_before(lhs);
}

void CheckNewVaultDoesntConflict(const VaultInfo& new_vault, const VaultInfo& existing_vault) {
  if (new_vault.pmid_and_signer && existing_vault.pmid_and_signer &&
      new_vault.pmid_and_signer->first.name() == existing_vault.pmid_and_signer->first.name()) {
    LOG(kError) << "Vault process with Pmid "
                << DebugId(new_vault.pmid_and_signer->first.name().value) << " already exists.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }

  if (new_vault.vault_dir == existing_vault.vault_dir) {
    LOG(kError) << "Vault process with vault dir " << new_vault.vault_dir << " already exists.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }

  if (new_vault.label == existing_vault.label) {
    LOG(kError) << "Vault process with label " << new_vault.label.string() << " already exists.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }

  if (ConnectionsEqual(new_vault.tcp_connection, existing_vault.tcp_connection)) {
    LOG(kError) << "Vault process with this tcp_connection already exists.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }
}

}  // unnamed namespace

ProcessManager::Child::Child(VaultInfo info, boost::asio::io_service &io_service, int restarts)
    : info(std::move(info)),
      on_exit(),
      timer(maidsafe::make_unique<Timer>(io_service)),
      restart_count(restarts),
      process_args(),
      status(ProcessStatus::kBeforeStarted),
#ifdef MAIDSAFE_WIN32
      process(PROCESS_INFORMATION()),
      handle(io_service) {}
#else
      process(0),
      signal_set(maidsafe::make_unique<boost::asio::signal_set>(io_service, SIGCHLD)) {}
#endif

ProcessManager::Child::Child(Child&& other)
    : info(std::move(other.info)),
      on_exit(std::move(other.on_exit)),
      timer(std::move(other.timer)),
      restart_count(std::move(other.restart_count)),
      process_args(std::move(other.process_args)),
      status(std::move(other.status)),
      process(std::move(other.process)),
#ifdef MAIDSAFE_WIN32
      handle(std::move(other.handle)) {}
#else
      signal_set(std::move(other.signal_set)) {}
#endif

ProcessManager::Child& ProcessManager::Child::operator=(Child other) {
  swap(*this, other);
  return *this;
}

void swap(ProcessManager::Child& lhs, ProcessManager::Child& rhs){
  using std::swap;
  swap(lhs.info, rhs.info);
  swap(lhs.on_exit, rhs.on_exit);
  swap(lhs.timer, rhs.timer);
  swap(lhs.restart_count, rhs.restart_count);
  swap(lhs.process_args, rhs.process_args);
  swap(lhs.status, rhs.status);
  swap(lhs.process, rhs.process);
#ifdef MAIDSAFE_WIN32
  swap(lhs.handle, rhs.handle);
#else
  swap(lhs.signal_set, rhs.signal_set);
#endif
}



ProcessManager::ProcessManager(boost::asio::io_service &io_service, fs::path vault_executable_path,
                               Port listening_port)
    : io_service_(io_service),
      kListeningPort_(listening_port),
      kVaultExecutablePath_(vault_executable_path),
      vaults_(),
      mutex_() {
  static_assert(std::is_same<ProcessId, process::ProcessId>::value,
                "process::ProcessId is statically checked as being of suitable size for holding a "
                "pid_t or DWORD, so vault_manager::ProcessId should use the same type.");
  boost::system::error_code ec;
  if (!fs::exists(kVaultExecutablePath_, ec) || ec) {
    LOG(kError) << kVaultExecutablePath_ << " doesn't exist.  " << (ec ? ec.message() : "");
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  if (!fs::is_regular_file(kVaultExecutablePath_, ec) || ec) {
    LOG(kError) << kVaultExecutablePath_ << " is not a regular file.  " << (ec ? ec.message() : "");
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  if (fs::is_symlink(kVaultExecutablePath_, ec) || ec) {
    LOG(kError) << kVaultExecutablePath_ << " is a symlink.  " << (ec ? ec.message() : "");
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  LOG(kVerbose) << "Vault executable found at " << kVaultExecutablePath_;
}

std::vector<VaultInfo> ProcessManager::GetAll() const {
  std::vector<VaultInfo> all_vaults;
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& vault : vaults_)
    all_vaults.push_back(vault.info);
  return all_vaults;
}

void ProcessManager::AddProcess(VaultInfo info, int restart_count) {
  if (info.vault_dir.empty() || !info.label.IsInitialised() || !info.pmid_and_signer) {
    LOG(kError) << "Can't add vault: vault_dir path and/or vault label and/or Pmid is empty.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  if (restart_count > kMaxVaultRestarts) {
    LOG(kError) << "Can't add vault process - too many restarts.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  std::lock_guard<std::mutex> lock{ mutex_ };
  for (const auto& vault : vaults_)
    CheckNewVaultDoesntConflict(info, vault.info);

  // emplace offers strong exception guarantee - only need to cover subsequent calls.
  auto itr(vaults_.emplace(std::end(vaults_), Child{ info, io_service_, restart_count }));
  on_scope_exit strong_guarantee{ [this, itr] { vaults_.erase(itr); } };
  StartProcess(itr);
  strong_guarantee.Release();
}

VaultInfo ProcessManager::HandleVaultStarted(TcpConnectionPtr connection, ProcessId process_id) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, process_id](const Child& vault) {
                          return GetProcessId(vault) == process_id;
                        }));
  if (itr == std::end(vaults_)) {
    LOG(kError) << "Failed to find vault with process ID " << process_id << " in child processes.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  }
  itr->timer->cancel();
  itr->info.tcp_connection = connection;
  itr->status = ProcessStatus::kRunning;
  return itr->info;
}

void ProcessManager::AssignOwner(const NonEmptyString& label,
                                 const passport::PublicMaid::Name& owner_name,
                                 DiskUsage max_disk_usage) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(DoFind(label));
  itr->info.owner_name = owner_name;
  itr->info.max_disk_usage = max_disk_usage;
}

void ProcessManager::StopProcess(TcpConnectionPtr connection, OnExitFunctor on_exit_functor) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, connection](const Child& vault) {
                          return ConnectionsEqual(vault.info.tcp_connection, connection);
                        }));
  if (itr == std::end(vaults_)) {
    LOG(kWarning) << "Vault process doesn't exist.";
    return;
  }
  itr->on_exit = on_exit_functor;
  itr->status = ProcessStatus::kStopping;
  StopProcess(*itr);
}

bool ProcessManager::HandleConnectionClosed(TcpConnectionPtr connection) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, connection](const Child& vault) {
                          return ConnectionsEqual(vault.info.tcp_connection, connection);
                        }));
  if (itr == std::end(vaults_)) {
    LOG(kWarning) << "Vault process doesn't exist.";
    return false;
  }
  // Set the timer to stop the process without setting the status to kStopping.  This will cause the
  // vault to be restarted unless it is explicitly stopped before the timer expires.
  NonEmptyString label{ itr->info.label };
  itr->timer->expires_from_now(kRpcTimeout);
  itr->timer->async_wait([this, label](const boost::system::error_code& error_code) {
    if (error_code && error_code == boost::asio::error::operation_aborted) {
      LOG(kVerbose) << "Connection closed timer cancelled OK.";
      return;
    }
    LOG(kWarning) << "Timed out after connection closed; restarting the vault.";
    OnProcessExit(label, -1, true);
  });
  return true;
}

void ProcessManager::StartProcess(std::vector<Child>::iterator itr) {
  if (itr->status != ProcessStatus::kBeforeStarted) {
    LOG(kError) << "Process has already been started.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }

  std::vector<std::string> args{ 1, kVaultExecutablePath_.string() };
  args.emplace_back(std::to_string(kListeningPort_));
  args.insert(std::end(args), std::begin(itr->process_args), std::end(itr->process_args));

  NonEmptyString label{ itr->info.label };

#ifndef MAIDSAFE_WIN32
  itr->signal_set->async_wait([this, label](const boost::system::error_code&, int) {
    int exit_code;
    wait(&exit_code);
    OnProcessExit(label, BOOST_PROCESS_EXITSTATUS(exit_code));
  });
#endif

  itr->process = bp::execute(
      bp::initializers::run_exe(kVaultExecutablePath_),
      bp::initializers::set_cmd_line(process::ConstructCommandLine(args)),
#ifndef MAIDSAFE_WIN32
      bp::initializers::notify_io_service(io_service_),
#endif
      bp::initializers::throw_on_error(),
      bp::initializers::inherit_env());

  itr->status = ProcessStatus::kStarting;

#ifdef MAIDSAFE_WIN32
  HANDLE copied_handle;
  DuplicateHandle(GetCurrentProcess(), itr->process.process_handle(), GetCurrentProcess(),
                  &copied_handle, 0, FALSE, DUPLICATE_SAME_ACCESS);
  itr->handle.assign(copied_handle);
  HANDLE native_handle{ itr->handle.native_handle() };
  itr->handle.async_wait([this, label, native_handle](const boost::system::error_code&) {
    DWORD exit_code;
    GetExitCodeProcess(native_handle, &exit_code);
    OnProcessExit(label, BOOST_PROCESS_EXITSTATUS(exit_code));
  });
#endif

  itr->timer->expires_from_now(kRpcTimeout);
  itr->timer->async_wait([this, label](const boost::system::error_code& error_code) {
    if (error_code && error_code == boost::asio::error::operation_aborted) {
      LOG(kVerbose) << "New process timer cancelled OK.";
      return;
    }
    LOG(kWarning) << "Timed out waiting for new process to connect via TCP.";
    OnProcessExit(label, -1, true);
  });
}

void ProcessManager::StopProcess(Child& vault) {
  NonEmptyString label{ vault.info.label };
  vault.timer->expires_from_now(kVaultStopTimeout);
  vault.timer->async_wait([this, label](const boost::system::error_code& error_code) {
    if (error_code && error_code == boost::asio::error::operation_aborted) {
      LOG(kVerbose) << "Vault termination timer cancelled OK.";
      return;
    }
    LOG(kWarning) << "Timed out waiting for Vault to stop; terminating now.";
    OnProcessExit(label, -1, true);
  });
}

VaultInfo ProcessManager::Find(const NonEmptyString& label) const {
  std::lock_guard<std::mutex> lock{ mutex_ };
  return DoFind(label)->info;
}

std::vector<ProcessManager::Child>::const_iterator ProcessManager::DoFind(
    const NonEmptyString& label) const {
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, &label](const Child& vault) {
                          return vault.info.label == label;
                        }));
  if (itr == std::end(vaults_)) {
    LOG(kError) << "Vault process with label " << label.string() << " doesn't exist.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  }
  return itr;
}

std::vector<ProcessManager::Child>::iterator ProcessManager::DoFind(const NonEmptyString& label) {
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, &label](const Child& vault) {
                          return vault.info.label == label;
                        }));
  if (itr == std::end(vaults_)) {
    LOG(kError) << "Vault process with label " << label.string() << " doesn't exist.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  }
  return itr;
}

ProcessId ProcessManager::GetProcessId(const Child& vault) const {
#ifdef MAIDSAFE_WIN32
  return static_cast<ProcessId>(vault.process.proc_info.dwProcessId);
#else
  return static_cast<ProcessId>(vault.process.pid);
#endif
}

bool ProcessManager::IsRunning(const Child& vault) const {
  try {
#ifdef MAIDSAFE_WIN32
    return process::IsRunning(vault.process.process_handle());
#else
    return process::IsRunning(vault.process.pid);
#endif
  }
  catch (const std::exception& e) {
    LOG(kInfo) << boost::diagnostic_information(e);
    return false;
  }
}

void ProcessManager::OnProcessExit(const NonEmptyString& label, int exit_code, bool terminate) {
  OnExitFunctor on_exit;
  VaultInfo vault_info;
  int restart_count(-1);
  {
    std::lock_guard<std::mutex> lock{ mutex_ };
    auto child_itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                   [this, &label](const Child& vault) { return vault.info.label == label; }));
    if (child_itr == std::end(vaults_))
      return;
    on_exit = child_itr->on_exit;
    if (child_itr->status != ProcessStatus::kStopping) {  // Unexpected exit - try to restart.
      restart_count = child_itr->restart_count;
      vault_info = child_itr->info;
      vault_info.tcp_connection.reset();
    }

    if (terminate)
      TerminateProcess(child_itr);

    child_itr->info.tcp_connection->Close();
    vaults_.erase(child_itr);
  }

  if (on_exit) {
    if (terminate)
      on_exit(MakeError(VaultManagerErrors::vault_terminated), -1);
    else if (exit_code == 0)
      on_exit(MakeError(CommonErrors::success), exit_code);
    else
      on_exit(MakeError(VaultManagerErrors::vault_exited_with_error), exit_code);
  }

  if (restart_count >= 0 && restart_count < kMaxVaultRestarts) {
    io_service_.post([vault_info, restart_count, this] {
      try {
        AddProcess(std::move(vault_info), restart_count + 1);
      }
      catch (const std::exception& e) {
        LOG(kError) << "Failed restarting vault: " << boost::diagnostic_information(e);
      }
    });
  }
}

void ProcessManager::TerminateProcess(std::vector<Child>::iterator itr) {
  boost::system::error_code ec;
  bp::terminate(itr->process, ec);
  if (ec)
    LOG(kError) << "Error while terminating vault: " << ec.message();
}

}  // namespace vault_manager

}  // namespace maidsafe
