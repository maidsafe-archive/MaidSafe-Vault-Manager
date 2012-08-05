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

#include "maidsafe/private/process_manager.h"

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

#include "maidsafe/private/controller_messages_pb.h"


namespace bp = boost::process;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

bool Process::SetProcessName(std::string process_name, std::string parent_path) {
  std::string path_string(parent_path.empty() ? fs::current_path().string() : parent_path);
  fs::path executable_path(fs::path(parent_path) / process_name);
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
  process_name_ = executable_path.string();
  return true;
}

void Process::AddArgument(std::string argument) {
  args_.push_back(argument);
}

std::string Process::ProcessName() const {
  return process_name_;
}

std::vector<std::string> Process::Args() const {
  return args_;
}



ProcessInfo::ProcessInfo(ProcessInfo&& other)
    : process(std::move(other.process)),
      thread(std::move(other.thread)),
      id(std::move(other.id)),
      port(std::move(other.port)),
      restart_count(std::move(other.restart_count)),
      done(std::move(other.done)) {}

ProcessInfo& ProcessInfo::operator=(ProcessInfo&& other) {
  process = std::move(other.process);
  thread = std::move(other.thread);
  id = std::move(other.id);
  port = std::move(other.port);
  restart_count = std::move(other.restart_count);
  done = std::move(other.done);
  return *this;
}



ProcessManager::ProcessManager() : processes_(), mutex_() {}

ProcessManager::~ProcessManager() {
  TerminateAll();
}

std::string ProcessManager::AddProcess(Process process, uint16_t port) {
  ProcessInfo info;
  std::string id(RandomAlphaNumericString(16));
  info.id = id;
  info.done = false;
  info.restart_count = 0;
  info.port = port;
  LOG(kInfo) << "Restart count on init: " << info.restart_count;
  process.AddArgument("--vmid");
  process.AddArgument(info.id + "-" + boost::lexical_cast<std::string>(info.port));
  LOG(kInfo) << "Process Arguments: ";
  for (std::string i : process.Args())
    LOG(kInfo) << i;
  info.process = process;
  std::lock_guard<std::mutex> lock(mutex_);
  processes_.push_back(std::move(info));
  return id;
}

int32_t ProcessManager::NumberOfProcesses() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return static_cast<int32_t>(processes_.size());
}

int32_t ProcessManager::NumberOfLiveProcesses() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return static_cast<int32_t>(
      std::count_if(processes_.begin(),
                    processes_.end(),
                    [](const ProcessInfo& process_info) {
                      return !process_info.done && process_info.thread.joinable();
                    }));
}

int32_t ProcessManager::NumberOfSleepingProcesses() const {
  std::lock_guard<std::mutex> lock(mutex_);
  return static_cast<int32_t>(
      std::count_if(processes_.begin(),
                    processes_.end(),
                    [](const ProcessInfo& process_info) { return !process_info.done; }));  // NOLINT (Fraser)
}

std::vector<ProcessInfo>::iterator ProcessManager::FindProcess(std::string id) {
  return std::find_if(processes_.begin(),
                      processes_.end(),
                      [id] (ProcessInfo &process_info) { return (process_info.id == id); });  // NOLINT (Fraser)
}

void ProcessManager::StartProcess(std::string id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(id);
  if (itr == processes_.end())
    return;
  (*itr).done = false;
  (*itr).restart_count = 0;
  LOG(kInfo) << "StartProcess: AddStatus. ID: " << id;
  // ProcessManagerStruct status;
  // status.instruction = ProcessInstruction::kRun;
  // AddStatus(id, status);
  (*itr).thread = std::move(boost::thread([=] { RunProcess(id, false, false); }));  // NOLINT (Fraser)
}

void ProcessManager::RunProcess(std::string id, bool restart, bool logging) {
  std::string process_name;
  std::vector<std::string> process_args;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    auto itr = FindProcess(id);
    if (itr == processes_.end()) {
      LOG(kError) << "RunProcess: process with specified VMID cannot be found";
      return;
    }
    process_name = (*itr).process.ProcessName();
    process_args = (*itr).process.Args();
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

  bp::child child(bp::launch(process_name, process_args, context));

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
  LOG(kInfo) << "Process " << id << " completes. Output: ";
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
    auto itr(FindProcess(id));
    LOG(kInfo) << "Restart count = " << (*itr).restart_count;
    if ((*itr).done)
      return;

    if ((*itr).restart_count > 4) {
      LOG(kInfo) << "A process " << (*itr).id << " is consistently failing. Stopping..."
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
  RunProcess(id, true, logging);
}

void ProcessManager::LetProcessDie(std::string id) {
  LOG(kInfo) << "LetProcessDie: ID: " << id;
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(id);
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

void ProcessManager::KillProcess(std::string id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(id);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
  // SetInstruction(id, ProcessInstruction::kTerminate);
}

void ProcessManager::StopProcess(std::string id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(id);
  if (itr == processes_.end())
    return;
  (*itr).done = true;
  // SetInstruction(id, ProcessInstruction::kStop);
}

void ProcessManager::RestartProcess(std::string id) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr = FindProcess(id);
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
      LOG(kInfo) << "TerminateAll: SetInstruction to kTerminate";
      SetInstruction(i.id, ProcessInstruction::kTerminate);
    }*/
    if (process.thread.joinable())
      process.thread.join();
  }
  processes_.clear();
}

}  // namespace priv

}  // namespace maidsafe
