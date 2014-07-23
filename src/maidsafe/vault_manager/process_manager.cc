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

#ifdef MAIDSAFE_BSD
extern "C" char **environ;
#endif

#ifdef _MSC_VER
#pragma warning(push)
#pragma warning(disable : 4702)
#endif
#include "boost/process/execute.hpp"
#ifdef _MSC_VER
#pragma warning(pop)
#endif
#include "boost/process/initializers.hpp"
#include "boost/process/mitigate.hpp"
#include "boost/process/terminate.hpp"
#include "boost/process/wait_for_exit.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/process.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/visualiser_log.h"

#include "maidsafe/vault_manager/dispatcher.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.pb.h"

namespace bp = boost::process;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace {

bool ConnectionsEqual(const tcp::ConnectionPtr& lhs, const tcp::ConnectionPtr& rhs) {
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
      process(0) {}
#endif

ProcessManager::Child::Child(Child&& other)
    : info(std::move(other.info)),
      on_exit(std::move(other.on_exit)),
      timer(std::move(other.timer)),
      restart_count(std::move(other.restart_count)),
      process_args(std::move(other.process_args)),
      status(std::move(other.status)),
#ifdef MAIDSAFE_WIN32
      process(std::move(other.process)),
      handle(std::move(other.handle)) {}
#else
      process(std::move(other.process)) {}
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
#endif
}



ProcessManager::ProcessManager(boost::asio::io_service &io_service, fs::path vault_executable_path,
                               tcp::Port listening_port)
    : io_service_(io_service),
#ifndef MAIDSAFE_WIN32
      signal_set_(io_service_, SIGCHLD),
#endif
      stop_all_flag_(),
      kListeningPort_(listening_port),
      kVaultExecutablePath_(vault_executable_path),
      vaults_() {
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
  InitSignalHandler();
}

std::shared_ptr<ProcessManager> ProcessManager::MakeShared(
    boost::asio::io_service& io_service, boost::filesystem::path vault_executable_path,
    tcp::Port listening_port) {
  return std::shared_ptr<ProcessManager>{ new ProcessManager{ io_service, vault_executable_path,
                                                              listening_port } };
}

ProcessManager::~ProcessManager() {
  assert(vaults_.empty());
}

void ProcessManager::StopAll() {
  std::call_once(stop_all_flag_, [this] {
    for (const auto& vault : vaults_)
      StopProcess(vault.info.tcp_connection);
#ifndef MAIDSAFE_WIN32
    boost::system::error_code ignored_ec;
    signal_set_.cancel(ignored_ec);
#endif
  });
}

std::vector<VaultInfo> ProcessManager::GetAll() const {
  std::vector<VaultInfo> all_vaults;
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
  for (const auto& vault : vaults_)
    CheckNewVaultDoesntConflict(info, vault.info);

  // emplace offers strong exception guarantee - only need to cover subsequent calls.
  auto itr(vaults_.emplace(std::end(vaults_), Child{ info, io_service_, restart_count }));
  on_scope_exit strong_guarantee{ [this, itr] { vaults_.erase(itr); } };
  StartProcess(itr);
  strong_guarantee.Release();
}

VaultInfo ProcessManager::HandleVaultStarted(tcp::ConnectionPtr connection, ProcessId process_id) {
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
  auto itr(DoFind(label));
  itr->info.owner_name = owner_name;
  itr->info.max_disk_usage = max_disk_usage;
}

void ProcessManager::StartProcess(std::vector<Child>::iterator itr) {
  if (itr->status != ProcessStatus::kBeforeStarted) {
    LOG(kError) << "Process has already been started.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }

  std::vector<std::string> args{ 1, kVaultExecutablePath_.string() };
  args.emplace_back(std::to_string(kListeningPort_));
  args.emplace_back("--log_folder " + (itr->info.vault_dir / "logs").string());
  args.insert(std::end(args), std::begin(itr->process_args), std::end(itr->process_args));

  NonEmptyString label{ itr->info.label };
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

void ProcessManager::InitSignalHandler() {
#ifndef MAIDSAFE_WIN32
  LOG(kVerbose) << "Initialising signal handler.";
  signal_set_.async_wait([this](const boost::system::error_code& error_code, int signum) {
    if (error_code && error_code == boost::asio::error::operation_aborted) {
      LOG(kVerbose) << "Cancelled waiting for SIGCHLD signal.";
      return;
    }

    maidsafe::on_scope_exit init_on_exit([this]() { InitSignalHandler(); });

    if (signum != SIGCHLD) {
      LOG(kWarning) << "Process ID " << process::GetProcessId() << " received signal " << signum;
      return;
    }

    int exit_code;
    ProcessId process_id{ static_cast<ProcessId>(wait(&exit_code)) };
    LOG(kWarning) << "Process ID " << process::GetProcessId() << " received SIGCHLD pid: "
                  << process_id;
    if (process_id == process::GetProcessId())
      return;

    auto child_itr(std::find_if(std::begin(vaults_), std::end(vaults_),
        [this, process_id](const Child& vault) { return GetProcessId(vault) == process_id; }));
    if (child_itr == std::end(vaults_))
      return;

    OnProcessExit(child_itr->info.label, BOOST_PROCESS_EXITSTATUS(exit_code));
  });
#endif
}

void ProcessManager::StopProcess(tcp::ConnectionPtr connection, OnExitFunctor on_exit_functor) {
  auto itr(std::begin(vaults_));
  try {
    itr = DoFind(connection);
  }
  catch (const std::exception& e) {
    LOG(kError) << "Vault process doesn't exist: " << boost::diagnostic_information(e);
    return;
  }
  itr->on_exit = on_exit_functor;
  itr->status = ProcessStatus::kStopping;
  SendVaultShutdownRequest(itr->info.tcp_connection);
  NonEmptyString label{ itr->info.label };
  itr->timer->expires_from_now(kVaultStopTimeout);
  itr->timer->async_wait([this, label](const boost::system::error_code& error_code) {
    if (error_code && error_code == boost::asio::error::operation_aborted) {
      LOG(kVerbose) << "Vault termination timer cancelled OK.";
      return;
    }
    LOG(kWarning) << "Timed out waiting for Vault to stop; terminating now.";
    OnProcessExit(label, -1, true);
  });
}

bool ProcessManager::HandleConnectionClosed(tcp::ConnectionPtr connection) {
  try {
    OnProcessExit(DoFind(connection)->info.label, -1, true);
  }
  catch (const maidsafe_error& error) {
    if (error.code() == make_error_code(CommonErrors::no_such_element))
      return false;
    throw;
  }
  return true;
}

VaultInfo ProcessManager::Find(const NonEmptyString& label) const {
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

VaultInfo ProcessManager::Find(tcp::ConnectionPtr connection) const {
  return DoFind(connection)->info;
}

std::vector<ProcessManager::Child>::const_iterator ProcessManager::DoFind(
    tcp::ConnectionPtr connection) const {
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, connection](const Child& vault) {
                          return ConnectionsEqual(vault.info.tcp_connection, connection);
                        }));
  if (itr == std::end(vaults_))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  return itr;
}

std::vector<ProcessManager::Child>::iterator ProcessManager::DoFind(tcp::ConnectionPtr connection) {
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, connection](const Child& vault) {
                          return ConnectionsEqual(vault.info.tcp_connection, connection);
                        }));
  if (itr == std::end(vaults_))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
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
  auto child_itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                  [this, &label](const Child& vault) { return vault.info.label == label; }));
  if (child_itr == std::end(vaults_))
    return;

  VaultInfo vault_info;
  int restart_count{ -1 };
  if (child_itr->status != ProcessStatus::kStopping) {  // Unexpected exit - try to restart.
    restart_count = child_itr->restart_count;
    vault_info = child_itr->info;
    LOG(kError) << "Vault " << DebugId(vault_info.pmid_and_signer->first.name().value)
                << " stopped unexpectedly";
#ifdef USE_VLOGGING
    log::VisualiserLogMessage::SendVaultStoppedMessage(
        DebugId(vault_info.pmid_and_signer->first.name().value),
        vault_info.vlog_session_id, exit_code);
#endif
    if (vault_info.tcp_connection) {
      vault_info.tcp_connection->Close();
      vault_info.tcp_connection.reset();
    }
  }

  bool is_running{ IsRunning(*child_itr) };
  LOG(kVerbose) << "On exit for Vault " << label.string() << std::boolalpha << "  Is running: "
      << is_running << "   Exit code: " << exit_code << "   Terminate requested: " << terminate;
  if (terminate && is_running)
    TerminateProcess(child_itr);

  if (child_itr->info.tcp_connection)
    child_itr->info.tcp_connection->Close();

  OnExitFunctor on_exit{ child_itr->on_exit };
  vaults_.erase(child_itr);

  InvokeOnExitFunctor(on_exit, exit_code, terminate);
  RestartIfRequired(restart_count, std::move(vault_info));
}

void ProcessManager::TerminateProcess(std::vector<Child>::iterator itr) {
  boost::system::error_code ec;
  bp::terminate(itr->process, ec);
  if (ec)
    LOG(kWarning) << "Error while terminating vault: " << ec.message();
}

void ProcessManager::InvokeOnExitFunctor(OnExitFunctor on_exit, int exit_code, bool terminate) {
  if (!on_exit)
    return;

  try {
    if (terminate)
      on_exit(MakeError(VaultManagerErrors::vault_terminated), -1);
    else if (exit_code == 0)
      on_exit(MakeError(CommonErrors::success), exit_code);
    else
      on_exit(MakeError(VaultManagerErrors::vault_exited_with_error), exit_code);
  }
  catch (const std::exception& e) {
    LOG(kError) << "Error executing on_exit functor: " << boost::diagnostic_information(e);
  }
  catch (...) {
    LOG(kError) << "Unknown error type while executing on_exit functor.";
  }
}

void ProcessManager::RestartIfRequired(int restart_count, VaultInfo vault_info) {
  if (restart_count < 0 || restart_count >= kMaxVaultRestarts)
    return;

  LOG(kWarning) << "Restarting vault " << vault_info.label.string();
  io_service_.post([vault_info, restart_count, this] {
    try {
      AddProcess(std::move(vault_info), restart_count + 1);
    }
    catch (const std::exception& e) {
      LOG(kError) << "Failed restarting vault: " << boost::diagnostic_information(e);
    }
  });
}

}  // namespace vault_manager

}  // namespace maidsafe
