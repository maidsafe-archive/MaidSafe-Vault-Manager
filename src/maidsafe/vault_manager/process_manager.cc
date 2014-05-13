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
//#include <chrono>
#include <type_traits>

//#include "boost/filesystem/fstream.hpp"
//#include "boost/filesystem/operations.hpp"
#include "boost/process/execute.hpp"
#include "boost/process/initializers.hpp"
#include "boost/process/wait_for_exit.hpp"
#include "boost/process/terminate.hpp"
//#include "boost/system/error_code.hpp"
//#include "boost/iostreams/device/file_descriptor.hpp"
//
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/process.h"
//#include "maidsafe/common/rsa.h"
//#include "maidsafe/common/utils.h"
//
#include "maidsafe/vault_manager/dispatcher.h"
//#include "maidsafe/vault_manager/controller_messages.pb.h"
//#include "maidsafe/vault_manager/local_tcp_transport.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.pb.h"

namespace bp = boost::process;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace {

bool IsRunning(const VaultInfo& vault_info) {
  try {
#ifdef MAIDSAFE_WIN32
    return process::IsRunning(vault_info.process.process_handle());
#else
    return process::IsRunning(vault_info.process.pid);
#endif
  }
  catch (const std::exception& e) {
    LOG(kInfo) << boost::diagnostic_information(e);
    return false;
  }
}

}  // unnamed namespace

ProcessManager::ProcessManager() : vaults_(), mutex_(), cond_var_() {
  static_assert(std::is_same<ProcessId, process::ProcessId>::value,
                "process::ProcessId is statically checked as being of suitable size for holding a "
                "pid_t or DWORD, so vault_manager::ProcessId should use the same type.");
}

ProcessManager::~ProcessManager() {
  std::vector<std::future<void>> process_stops;
  {
    std::lock_guard<std::mutex> lock{ mutex_ };
    std::for_each(std::begin(vaults_), std::end(vaults_),
                  [this, &process_stops](VaultInfo& vault_info) {
                    process_stops.emplace_back(StopProcess(vault_info));
                  });
  }
  for (auto& process_stop : process_stops) {
    try {
      process_stop.get();
    }
    catch (const std::exception& e) {
      LOG(kError) << "Vault process failed to stop: " << boost::diagnostic_information(e);
    }
  }
}

void ProcessManager::AddVaultsDetailsToConfig(const crypto::AES256Key& symm_key,
                                              const crypto::AES256InitialisationVector& symm_iv,
                                              protobuf::VaultManagerConfig& config) const {
  config.clear_vault_info();
  std::lock_guard<std::mutex> lock(mutex_);
  for (const auto& vault : vaults_)
    ToProtobuf(symm_key, symm_iv, vault, config.add_vault_info());
}

void ProcessManager::AddProcess(VaultInfo vault_info) {
  if (vault_info.chunkstore_path.empty() || vault_info.process_args.empty()) {
    LOG(kError) << "Can't add vault process - chunkstore and/or command line args are empty.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  if (IsRunning(vault_info)) {
    LOG(kError) << "Can't add vault process - already running.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, &vault_info](const VaultInfo& vault) {
                          return vault.label == vault_info.label;
                        }));
  if (itr != std::end(vaults_)) {
    LOG(kError) << "Vault process with label " << vault_info.label.string() << " already exists.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }

  // emplace offers strong exception guarantee - only need to cover subsequent calls.
  itr = vaults_.emplace(std::end(vaults_), std::move(vault_info));
  on_scope_exit strong_guarantee{ [this, itr] { vaults_.erase(itr); } };
  StartProcess(itr);
  strong_guarantee.Release();
}

passport::PublicMaid::Name ProcessManager::HandleVaultStarted(TcpConnectionPtr connection,
    ProcessId process_id, crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
    const routing::BootstrapContacts& bootstrap_contacts) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, process_id](const VaultInfo& vault) {
                          return GetProcessId(vault.process) == process_id;
                        }));
  if (itr == std::end(vaults_)) {
    LOG(kError) << "Failed to find vault with process ID " << process_id << " in child processes.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  }
  itr->tcp_connection = connection;
  SendVaultStartedResponse(*itr, symm_key, symm_iv, bootstrap_contacts);
  return itr->owner_name;
}

void ProcessManager::AssignOwner(TcpConnectionPtr client_connection, VaultInfo vault_info) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(std::find_if(std::begin(vaults_), std::end(vaults_),
                        [this, &vault_info](const VaultInfo& vault) {
                          return vault.label == vault_info.label;
                        }));
  if (itr == std::end(vaults_)) {
    LOG(kError) << "Vault process with label " << vault_info.label.string() << " doesn't exist.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::no_such_element));
  }

  if (vault_info.chunkstore_path != itr->chunkstore_path) {
    // TODO(Fraser#5#): 2014-05-13 - Handle sending a "MoveChunkstoreRequest" to avoid stopping then
    //                               restarting the vault.
    SendVaultShutdownRequest(itr->tcp_connection);
    itr->chunkstore_path = vault_info.chunkstore_path;
    itr->max_disk_usage = vault_info.max_disk_usage;
    return;
  }

  if (vault_info.max_disk_usage != itr->max_disk_usage && vault_info.max_disk_usage != 0U) {
    SendMaxDiskUsageUpdate(itr->tcp_connection, vault_info.max_disk_usage);
    itr->max_disk_usage = vault_info.max_disk_usage;
  }

  SendVaultRunningResponse(client_connection, vault_info.label, itr->pmid_and_signer.get());
}

bool ProcessManager::HandleConnectionClosed(TcpConnectionPtr /*connection*/) {
                                                                                            return false;
}

void ProcessManager::StartProcess(std::vector<VaultInfo>::iterator itr) {
  if (!itr->stop_process) {
    itr->process = bp::execute(
        bp::initializers::run_exe(fs::path{ itr->process_args.front() }),
        bp::initializers::set_cmd_line(process::ConstructCommandLine(itr->process_args)),
        bp::initializers::throw_on_error(),
        bp::initializers::inherit_env());
  }
}

std::future<void> ProcessManager::StopProcess(VaultInfo& vault_info) {
  vault_info.stop_process = true;
  SendVaultShutdownRequest(vault_info.tcp_connection);
  return std::async([&]() {

  });
}





ProcessId ProcessManager::GetProcessId(const boost::process::child& child) const {
#ifdef MAIDSAFE_WIN32
  return static_cast<ProcessId>(child.proc_info.dwProcessId);
#else
  return static_cast<ProcessId>(child.pid);
#endif
}

/*
std::vector<ProcessManager::ProcessInfo>::iterator ProcessManager::FindProcess(ProcessIndex index) {
  return std::find_if(processes_.begin(), processes_.end(), [index](ProcessInfo & process_info) {
    return (process_info.index == index);
  });
}

void ProcessManager::StartProcess(ProcessIndex index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = false;
  (*itr).restart_count = 0;
  LOG(kInfo) << "StartProcess: AddStatus. ID: " << index;
  (*itr).thread =
      std::move(boost::thread([=] { RunProcess(index, false, false); }));
}

void ProcessManager::RunProcess(ProcessIndex index, bool restart, bool logging) {
  std::string process_name;
  std::vector<std::string> process_args;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto itr = FindProcess(index);
    if (itr == processes_.end()) {
      LOG(kError) << "RunProcess: process with specified VMID cannot be found";
      return;
    }
    process_name = (*itr).process.name();
    process_args = (*itr).process.args();
  }

  if (restart) {
    Sleep(std::chrono::milliseconds(600));
    // SetInstruction(id, ProcessInstruction::kRun);
    //    if (logging) {
    //      log::FilterMap filter;
    //      filter["*"] = log::kVerbose;
    //      log::Logging::instance().SetFilter(filter);
    //      log::Logging::instance().SetAsync(true);
    //    }
  }
  boost::system::error_code error_code;
  // TODO(Fraser#5#): 2012-08-29 - Handle logging to a file.  See:
  // http://www.highscore.de/boost/process0.5/boost_process/tutorial.html#boost_process.tutorial.setting_up_standard_streams
  // NOLINT (Fraser)
  SetProcessStatus(index, ProcessStatus::kRunning);
  bp::child child(bp::execute(
      bp::initializers::run_exe(process_name),
      bp::initializers::set_cmd_line(process::ConstructCommandLine(process_args)),
      bp::initializers::set_on_error(error_code),
      bp::initializers::inherit_env()));
  boost::system::error_code error;
  auto exit_code = wait_for_exit(child, error);
  if (error) {
    LOG(kError) << "Error waiting for child to exit: " << error.message();
  }
  SetProcessStatus(index, ProcessStatus::kStopped);
  LOG(kInfo) << "Process " << index << " has completed with exit code " << exit_code;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto itr(FindProcess(index));
    LOG(kInfo) << "Restart count = " << (*itr).restart_count;
    if ((*itr).done)
      return;

    if ((*itr).restart_count > 4) {
      LOG(kInfo) << "A process " << (*itr).index << " is consistently failing. Stopping..."
                 << " Restart count = " << (*itr).restart_count;
      return;
    }

    if ((*itr).restart_count < 3) {
      ++(*itr).restart_count;
      logging = false;
    } else {
      ++(*itr).restart_count;
      logging = true;
    }
  }
  RunProcess(index, true, logging);
}

void ProcessManager::LetProcessDie(ProcessIndex index) {
  LOG(kVerbose) << "LetProcessDie: ID: " << index;
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
}

void ProcessManager::LetAllProcessesDie() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& process : processes_)
    process.done = true;
}

void ProcessManager::WaitForProcesses() {
  bool done(false);
  boost::thread thread;
  while (!done) {
    done = true;
    {
      std::lock_guard<std::mutex> lock(mutex_);
      for (auto& process : processes_) {
        if (!process.done) {
          done = false;
          break;
        }
        if (process.thread.joinable()) {
          thread = std::move(process.thread);
          done = false;
          break;
        }
      }
    }
    thread.join();
    Sleep(std::chrono::milliseconds(100));
  }
}

void ProcessManager::KillProcess(ProcessIndex index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
  bp::terminate((*itr).child);
}

void ProcessManager::StopProcess(ProcessIndex index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
}

void ProcessManager::RestartProcess(ProcessIndex index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = false;
  // SetInstruction(id, ProcessInstruction::kTerminate);
}

ProcessStatus ProcessManager::GetProcessStatus(ProcessIndex index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return ProcessStatus::kError;
  return (*itr).status;
}

bool ProcessManager::WaitForProcessToStop(ProcessIndex index) {
  std::unique_lock<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return false;
  if (cond_var_.wait_for(lock, std::chrono::seconds(5), [&]()->bool {
        return (*itr).status != ProcessStatus::kRunning;
      }))
    return true;
  LOG(kError) << "Wait for process " << index << " to stop timed out. Terminating...";
  lock.unlock();
  KillProcess(index);
  return true;
}

bool ProcessManager::SetProcessStatus(ProcessIndex index, const ProcessStatus& status) {
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto itr = FindProcess(index);
    if (itr == processes_.end())
      return false;
    (*itr).status = status;
  }
  cond_var_.notify_all();
  return true;
}

void ProcessManager::TerminateAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& process : processes_) {
    LOG(kInfo) << "Terminating: " << process.index << ", port: " << process.port;
    if (process.thread.joinable() && process.status == ProcessStatus::kRunning)
      process.thread.join();
  }
  processes_.clear();
}
*/
}  // namespace vault_manager

}  // namespace maidsafe
