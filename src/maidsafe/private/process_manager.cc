/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "maidsafe/private/process_manager.h"

#include <thread>
#include <chrono>

#include <boost/process.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/filesystem.hpp>

#include <maidsafe/common/log.h>
#include <maidsafe/common/utils.h>

#include <string>
#include <vector>
#include <utility>
#include <algorithm>

namespace maidsafe {

  namespace bp = boost::process;
  namespace bi = boost::interprocess;

  typedef bi::allocator<TerminateStatus,
      bi::managed_shared_memory::segment_manager> TerminateAlloc;
  typedef bi::vector<TerminateStatus, TerminateAlloc> TerminateVector;

  bool Process::SetProcessName(std::string process_name) {
    std::string path_string(boost::filesystem::current_path().string());
    boost::system::error_code ec;
    boost::filesystem3::path proc(process_name);
    if (!boost::filesystem3::exists(proc, ec))
      return false;
    if (!boost::filesystem3::is_regular_file(proc, ec))
      return false;
    if (ec)
      return false;
    std::string exec = bp::find_executable_in_path(process_name, path_string);
    process_name_ = exec;
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

  ProcessInfo::ProcessInfo(ProcessInfo&& other) :
    process(), thread(), id(0), done(false) {
    process = std::move(other.process);
    thread = std::move(other.thread);
    id = std::move(other.id);
    done = std::move(other.done);
  }

  ProcessInfo& ProcessInfo::operator=(ProcessInfo&& other) {
    process = std::move(other.process);
    thread = std::move(other.thread);
    id = std::move(other.id);
    done = std::move(other.done);
    return *this;
  }

  ProcessManager::ProcessManager() :
    processes_(),
    process_count_(0),
    done_(false),
    process_id_(),
    shared_mem_name_(RandomAlphaNumericString(16)),
    shared_mem_() {
      boost::interprocess::shared_memory_object::remove(shared_mem_name_.c_str());
      shared_mem_ = bi::managed_shared_memory(bi::open_or_create, shared_mem_name_.c_str(), 4096);
      shared_mem_.construct<TerminateVector>("terminate_info")(shared_mem_.get_segment_manager());
    }

  ProcessManager::~ProcessManager() {
    TerminateAll();
    boost::interprocess::shared_memory_object::remove(shared_mem_name_.c_str());
  }

  int ProcessManager::AddProcess(Process process) {
    ProcessInfo info;
    info.id = ++process_id_;
    info.done = false;
    process.AddArgument("--pid");
    process.AddArgument(boost::lexical_cast<std::string>(info.id));
    process.AddArgument("--sharedmem");
    process.AddArgument(shared_mem_name_);
    LOG(kInfo) << "Process Arguments: ";
    for (std::string i : process.Args())
      LOG(kInfo) << i;
    info.process = process;
    processes_.push_back(std::move(info));
    return process_id_;
  }

  int32_t ProcessManager::NumberOfProcesses() {
    return processes_.size();
  }


  int32_t ProcessManager::NumberOfLiveProcesses() {
    int32_t count(0);
    for (auto &i : processes_) {
      if (!i.done && i.thread.joinable())
        ++count;
    }
    return count;
  }

  int32_t ProcessManager::NumberOfSleepingProcesses() {
    int32_t count(0);
    for (auto &i : processes_) {
      if (!i.done)
        ++count;
    }
    return count;
  }

  void ProcessManager::RunProcess(int32_t id, bool restart) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    if (restart) {
      boost::this_thread::sleep(boost::posix_time::milliseconds(600));
      SetTerminateFlag(id, TerminateStatus::kNoTerminate);
    }
    bp::context ctx;
    ctx.environment = bp::self::get_environment();
    ctx.stderr_behavior = bp::capture_stream();
    ctx.stdout_behavior = bp::capture_stream();
    bp::child c(bp::launch((*i).process.ProcessName(), (*i).process.Args(), ctx));
    bp::pistream& is = c.get_stdout();
    bp::pistream& is2 = c.get_stderr();
    std::string result;
    std::string line;
    while (std::getline(is, line)) {
      result += line;
    }
    result += "\nstd::err: ";
    while (std::getline(is2, line)) {
      result += line;
    }
    c.wait();
    LOG(kInfo) << "Process " << id << " completes. Output: ";
    LOG(kInfo) << result;
    if (!(*i).done)
      RunProcess(id, true);
  }

  void ProcessManager::KillProcess(int32_t id) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = true;
    LOG(kInfo) << "KillProcess: SetTerminateFlag";
    SetTerminateFlag(id, TerminateStatus::kTerminate);
  }

  void ProcessManager::RestartProcess(int32_t id) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = false;
    LOG(kInfo) << "RestartProcess: SetTerminateFlag";
    SetTerminateFlag(id, TerminateStatus::kTerminate);
  }

  void ProcessManager::StartProcess(int32_t id) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = false;
    LOG(kInfo) << "StartProcess: AddTerminateFlag";
    AddTerminateFlag(TerminateStatus::kNoTerminate);
    std::thread thd([=] { RunProcess(id, false); }); //NOLINT
    (*i).thread = std::move(thd);
  }

  void ProcessManager::LetProcessDie(int32_t id) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = true;
  }

  std::vector<ProcessInfo>::iterator ProcessManager::FindProcess(int32_t num) {
    int32_t id_to_find = num;
    return std::find_if(processes_.begin(), processes_.end(), [=] (ProcessInfo &j) {
      return (j.id == id_to_find);
    });
  }

  void ProcessManager::WaitForProcesses() {
    for (auto &i : processes_) {
      while (!i.done) {}
      i.thread.join();
    }
  }

  void ProcessManager::TerminateAll() {
    for (auto &i : processes_) {
      if (!CheckTerminateFlag(i.id)) {
        i.done = true;
        LOG(kInfo) << "TerminateAll: SetTerminateFlag";
        SetTerminateFlag(i.id, TerminateStatus::kTerminate);
      }
      if (i.thread.joinable())
        i.thread.join();
    }
    processes_.clear();
  }

  bool ProcessManager::AddTerminateFlag(TerminateStatus status) {
    std::pair<TerminateVector*, std::size_t> t =
        shared_mem_.find<TerminateVector>("terminate_info");
    if (t.first) {
      LOG(kInfo) << "AddTerminateFlag: vector is size " << (*t.first).size();
    } else {
      LOG(kError) << "AddTerminateFlag: failed to access IPC shared memory";
      return false;
    }
    (*t.first).push_back(status);
    LOG(kInfo) << "AddTerminateFlag: vector is now size " << (*t.first).size();
    return true;
  }

  bool ProcessManager::SetTerminateFlag(int32_t id, TerminateStatus status) {
    std::pair<TerminateVector*, std::size_t> t =
        shared_mem_.find<TerminateVector>("terminate_info");
    size_t size(0);
    if (t.first) {
      size = (*t.first).size();
      LOG(kInfo) << "SetTerminateFlag: vector is size " << size;
    } else {
      LOG(kError) << "SetTerminateFlag: failed to access IPC shared memory";
      return false;
    }
    if (size <= static_cast<size_t>(id - 1) || id - 1 < 0) {
      LOG(kError) << "SetTerminateFlag: given process id is invalid or outwith range of "
                  << "terminate vector. Vector size: " << size << ", ID: " << id;
      return false;
    }
    (*t.first).at(id - 1) = status;
    return true;
  }
  bool ProcessManager::CheckTerminateFlag(int32_t id) {
    std::pair<TerminateVector*, std::size_t> t =
        shared_mem_.find<TerminateVector>("terminate_info");
    size_t size(0);
    if (t.first) {
      size = (*t.first).size();
    } else {
      LOG(kError) << "CheckTerminateFlag: failed to access IPC shared memory";
      return false;
    }
    if (size <= static_cast<size_t>(id - 1) || id - 1 < 0) {
      LOG(kError) << "SetTerminateFlag: given process id is invalid or outwith range of "
                  << "terminate vector. Vector size: " << size << ", index: " << id - 1;
      return false;
    }
    if ((*t.first).at(id - 1) == TerminateStatus::kTerminate)
      return true;
    return false;
  }
}  // namespace maidsafe
