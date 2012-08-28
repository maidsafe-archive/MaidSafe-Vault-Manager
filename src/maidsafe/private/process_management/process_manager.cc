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

#include "maidsafe/private/process_management/process_manager.h"

#include <algorithm>

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244 4250 4267)
#endif

#include "boost/process.hpp"

#ifdef __MSVC__
#  pragma warning(pop)
#endif

#include "boost/filesystem/fstream.hpp"
#include "boost/archive/text_oarchive.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/system/error_code.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/process_management/controller_messages_pb.h"
#include "maidsafe/private/process_management/local_tcp_transport.h"
#include "maidsafe/private/process_management/utils.h"


namespace bp = boost::process;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace process_management {

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
      done(std::move(other.done)) {}

ProcessManager::ProcessInfo& ProcessManager::ProcessInfo::operator=(
    ProcessManager::ProcessInfo&& other) {
  process = std::move(other.process);
  thread = std::move(other.thread);
  index = std::move(other.index);
  port = std::move(other.port);
  restart_count = std::move(other.restart_count);
  done = std::move(other.done);
  return *this;
}



ProcessManager::ProcessManager() : processes_(), current_max_id_(0), mutex_() {}

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
  // ProcessManagerStruct status;
  // status.instruction = ProcessInstruction::kRun;
  // AddStatus(id, status);
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
    if (logging) {
      log::FilterMap filter;
      filter["*"] = log::kVerbose;
      log::Logging::instance().SetFilter(filter);
      log::Logging::instance().SetAsync(true);
    }
  }
  bp::context context;
  context.environment = bp::self::get_environment();
  context.stderr_behavior = bp::capture_stream();
  context.stdout_behavior = bp::capture_stream();
  bp::child child;
  try {
    child = bp::child(bp::launch(process_name, process_args, context));
  }
  catch(const std::exception& e) {
    LOG(kError) << "Failed to launch " << process_name << "  : " << e.what();
    return;
  }

  bp::pistream& stdout_stream = child.get_stdout();
  bp::pistream& stderr_stream = child.get_stderr();
  std::string result;
  std::string line;
  while (std::getline(stdout_stream, line))
    result += line + '\n';

  bool stderr_message(false);
  while (std::getline(stderr_stream, line)) {
    if (!stderr_message) {
      stderr_message = true;
      result += "\nstd::err: ";
    }
    result += line + '\n';
  }

  if (logging) {
    fs::path filename("Logging.txt");
    fs::ofstream ofstream(filename);
    boost::archive::text_oarchive text_oarchive(ofstream);
    std::string line;
    std::string content;
    while (std::getline(stdout_stream, line))
      content += line + "\n";
    text_oarchive & content;
  }
#ifdef MAIDSAFE_WIN32
  child.wait();
#else
  bp::posix_status status = child.wait();
#endif
  LOG(kInfo) << "Process " << index << " completes. Output: ";
  LOG(kInfo) << result;
#ifndef MAIDSAFE_WIN32
  if (status.exited()) {
    LOG(kInfo) << "Program returned exit code " << status.exit_status();
  } else if (status.stopped()) {
    LOG(kInfo) << "Program stopped by signal " << status.stop_signal();
  } else if (status.signaled()) {
    LOG(kInfo) << "Program received signal " << status.term_signal();
    if (status.dumped_core())
      LOG(kInfo) << "Program also dumped core";
  } else {
    LOG(kInfo) << "Program terminated for unknown reason";
  }
#endif
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
    Sleep(boost::posix_time::milliseconds(10));
  }
}

void ProcessManager::KillProcess(const ProcessIndex& index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
  // SetInstruction(id, ProcessInstruction::kTerminate);
}

void ProcessManager::StopProcess(const ProcessIndex& index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
  // SetInstruction(id, ProcessInstruction::kStop);
}

void ProcessManager::RestartProcess(const ProcessIndex& index) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(index);
  if (itr == processes_.end())
    return;
  (*itr).done = false;
  // SetInstruction(id, ProcessInstruction::kTerminate);
}

void ProcessManager::TerminateAll() {
  std::lock_guard<std::mutex> lock(mutex_);
  for (auto& process : processes_) {
    /*if (CheckInstruction(i.id) != ProcessInstruction::kTerminate) {
      i.done = true;
      SetInstruction(i.id, ProcessInstruction::kTerminate);
    }*/
      LOG(kInfo) << "Terminating: " << process.index << ", port: " << process.port;
    if (process.thread.joinable())
      process.thread.join();
  }
  processes_.clear();
}

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
