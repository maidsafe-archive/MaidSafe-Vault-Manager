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

#include "maidsafe/private/lifestuff_manager/process_manager.h"

#include <algorithm>
#include <chrono>

#include "boost/filesystem/fstream.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/process/child.hpp"
#include "boost/process/execute.hpp"
#include "boost/process/initializers.hpp"
#include "boost/process/wait_for_exit.hpp"
#include "boost/process/terminate.hpp"
#include "boost/system/error_code.hpp"

#include "boost/iostreams/device/file_descriptor.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/lifestuff_manager/controller_messages_pb.h"
#include "maidsafe/private/lifestuff_manager/local_tcp_transport.h"
#include "maidsafe/private/lifestuff_manager/utils.h"


namespace bp = boost::process;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace {

#ifdef MAIDSAFE_WIN32
std::wstring StringToWstring(const std::string &input) {
  std::unique_ptr<wchar_t[]> buffer(new wchar_t[input.size()]);
  size_t num_chars = mbstowcs(buffer.get(), input.c_str(), input.size());
  return std::wstring(buffer.get(), num_chars);
}

std::wstring ConstructCommandLine(std::vector<std::string> process_args) {
  std::string args;
  for (auto arg : process_args)
    args += (arg + " ");
  return StringToWstring(args);
}
#else
std::string ConstructCommandLine(std::vector<std::string> process_args) {
  std::string args;
  for (auto arg : process_args)
    args += (arg + " ");
  return args;
}
#endif

}  // unnamed namespace

bool Process::SetExecutablePath(const fs::path& executable_path) {
  boost::system::error_code ec;
  if (!fs::exists(executable_path, ec) || ec) {
    LOG(kError) << executable_path << " doesn't exist.  " << (ec ? ec.message() : "");
    return false;
  }
  if (!fs::is_regular_file(executable_path, ec) || ec) {
    LOG(kError) << executable_path << " is not a regular file.  " << (ec ? ec.message() : "");
    return false;
  }
  if (fs::is_symlink(executable_path, ec) || ec) {
    LOG(kError) << executable_path << " is a symlink.  " << (ec ? ec.message() : "");
    return false;
  }
  LOG(kInfo) << "Executable found at " << executable_path.string();
  name_ = executable_path.string();
  args_.push_back(name_);
  return true;
}



ProcessManager::ProcessInfo::ProcessInfo(ProcessManager::ProcessInfo&& other)
    : process(std::move(other.process)),
      thread(std::move(other.thread)),
      index(std::move(other.index)),
      port(std::move(other.port)),
      restart_count(std::move(other.restart_count)),
      done(std::move(other.done)),
      status(std::move(other.status)),
      child(std::move(other.child)) {}

ProcessManager::ProcessInfo& ProcessManager::ProcessInfo::operator=(
    ProcessManager::ProcessInfo&& other) {
  process = std::move(other.process);
  thread = std::move(other.thread);
  index = std::move(other.index);
  port = std::move(other.port);
  restart_count = std::move(other.restart_count);
  done = std::move(other.done);
  status = std::move(other.status);
  child = std::move(other.child);
  return *this;
}



ProcessManager::ProcessManager() : processes_(), current_max_id_(0), mutex_(), cond_var_() {}

ProcessManager::~ProcessManager() {
  TerminateAll();
}

ProcessIndex ProcessManager::AddProcess(Process process, Port port) {
  if (process.name().empty()) {
    LOG(kError) << "Invalid process - executable path empty.";
    return kInvalidIndex();
  }
  ProcessInfo info;
  info.index = ++current_max_id_;
  info.done = false;
  info.status = ProcessStatus::kStopped;
  info.restart_count = 0;
  info.port = port;
  LOG(kVerbose) << "Restart count on init: " << info.restart_count;
  process.AddArgument("--vmid");
  process.AddArgument(detail::GenerateVmidParameter(info.index, info.port));
  info.process = process;
  std::lock_guard<std::mutex> lock(mutex_);
  processes_.push_back(std::move(info));
  return info.index;
}

size_t ProcessManager::NumberOfProcesses() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return processes_.size();
}

size_t ProcessManager::NumberOfLiveProcesses() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return std::count_if(processes_.begin(),
                       processes_.end(),
                       [](const ProcessInfo& process_info) {
                         return !process_info.done && process_info.thread.joinable();
                       });
}

size_t ProcessManager::NumberOfSleepingProcesses() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return std::count_if(processes_.begin(),
                       processes_.end(),
                       [](const ProcessInfo& process_info) { return !process_info.done; });  // NOLINT (Fraser)
}

std::vector<ProcessManager::ProcessInfo>::iterator ProcessManager::FindProcess(
    const ProcessIndex& index) {
  return std::find_if(processes_.begin(),
                      processes_.end(),
                      [index] (ProcessInfo &process_info) {
                        return (process_info.index == index);
                      });
}

void ProcessManager::StartProcess(const ProcessIndex& index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = false;
  (*itr).restart_count = 0;
  LOG(kInfo) << "StartProcess: AddStatus. ID: " << index;
  (*itr).thread = std::move(boost::thread([=] { RunProcess(index, false, false); }));  // NOLINT (Fraser)
}

void ProcessManager::RunProcess(const ProcessIndex& index, bool restart, bool logging) {
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
    Sleep(boost::posix_time::milliseconds(600));
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
  // http://www.highscore.de/boost/process0.5/boost_process/tutorial.html#boost_process.tutorial.setting_up_standard_streams  NOLINT (Fraser)
  SetProcessStatus(index, ProcessStatus::kRunning);
  bp::child child(bp::execute(
    bp::initializers::run_exe(process_name),
    bp::initializers::set_cmd_line(ConstructCommandLine(process_args)),
    bp::initializers::set_on_error(error_code),
    bp::initializers::inherit_env()
  ));
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

void ProcessManager::LetProcessDie(const ProcessIndex& index) {
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
    Sleep(boost::posix_time::milliseconds(100));
  }
}

void ProcessManager::KillProcess(const ProcessIndex& index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
  bp::terminate((*itr).child);
}

void ProcessManager::StopProcess(const ProcessIndex& index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
}

void ProcessManager::RestartProcess(const ProcessIndex& index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = false;
  // SetInstruction(id, ProcessInstruction::kTerminate);
}

ProcessStatus ProcessManager::GetProcessStatus(const ProcessIndex& index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return ProcessStatus::kError;
  return (*itr).status;
}

bool ProcessManager::WaitForProcessToStop(const ProcessIndex& index) {
  std::unique_lock<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return false;
  if (cond_var_.wait_for(lock, std::chrono::seconds(5), [&] ()->bool { return (*itr).status != ProcessStatus::kRunning; }))  //NOLINT (Philip)
    return true;
  LOG(kError) << "Wait for process " << index << " to stop timed out. Terminating...";
  lock.unlock();
  KillProcess(index);
  return true;
}

bool ProcessManager::SetProcessStatus(const ProcessIndex& index, const ProcessStatus& status) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return false;
  (*itr).status = status;
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

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe
