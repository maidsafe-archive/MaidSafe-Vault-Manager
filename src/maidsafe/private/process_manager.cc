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

#ifdef __MSVC__
# pragma warning(push)
# pragma warning(disable: 4250)
#endif

#include "maidsafe/private/process_manager.h"

#include <thread>
#include <chrono>
#include <boost/process.hpp>
#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/containers/string.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/filesystem.hpp>
#include <maidsafe/common/log.h>
#include <maidsafe/common/utils.h>
#include <maidsafe/common/rsa.h>

#include <string>
#include <vector>
#include <utility>
#include <algorithm>

#include "maidsafe/private/vault_identity_info_pb.h"

#include "boost/archive/text_oarchive.hpp"
#include "boost/archive/text_iarchive.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/filesystem/operations.hpp"

#include "boost/asio.hpp"

namespace maidsafe {

  namespace bp = boost::process;
  namespace bai = boost::asio::ip;

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
    LOG(kInfo) << "Executable found at " << exec;
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
    process(), thread(), id(), port(), restart_count(0), done(false) {
    process = std::move(other.process);
    thread = std::move(other.thread);
    id = std::move(other.id);
    port = std::move(other.port);
    restart_count = std::move(other.restart_count);
    done = std::move(other.done);
  }

  ProcessInfo& ProcessInfo::operator=(ProcessInfo&& other) {
    process = std::move(other.process);
    thread = std::move(other.thread);
    id = std::move(other.id);
    port = std::move(other.port);
    restart_count = std::move(other.restart_count);
    done = std::move(other.done);
    return *this;
  }

  ProcessManager::ProcessManager() :
    processes_(),
    process_info_mutex_(),
    process_count_(0),
    done_(false),
    current_port_(5483),
    io_service_() {}

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
    processes_.push_back(std::move(info));
    return id;
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

  void ProcessManager::RunProcess(std::string id, bool restart, bool logging) {
    auto i = FindProcess(id);
    if (i == processes_.end()) {
      LOG(kError) << "RunProcess: process with specified VMID cannot be found";
      return;
    }
    if (restart) {
      Sleep(boost::posix_time::milliseconds(600));
      // SetInstruction(id, ProcessInstruction::kRun);
      if (logging) {
        maidsafe::log::FilterMap filter;
        filter["*"] = maidsafe::log::kVerbose;
        maidsafe::log::Logging::instance().SetFilter(filter);
        maidsafe::log::Logging::instance().SetAsync(true);
        maidsafe::log::Logging::instance().SetColour(true);
      }
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
    maidsafe::rsa::Keys keys;
    maidsafe::rsa::GenerateKeyPair(&keys);
    std::string keys_string, account_name("account1");
    maidsafe::rsa::SerialiseKeys(keys, keys_string);
    maidsafe::priv::VaultIdentityInfo info;
    info.set_keys(keys_string);
    info.set_account_name(account_name);
    while (std::getline(is, line)) {
      result += line;
      result += "\n";
    }
    result += "\nstd::err: ";
    while (std::getline(is2, line)) {
      result += line;
      result += "\n";
    }

    if (logging) {
      fs::path filename("Logging.txt");
      fs::ofstream ofs(filename);
      boost::archive::text_oarchive oa(ofs);
      std::string line;
      std::string content;
      while (std::getline(is, line))
         content += line + "\n";
      oa & content;
    }
    bp::posix_status s = c.wait();
    i = FindProcess(id);
    LOG(kInfo) << "Process " << id << " completes. Output: ";
    LOG(kInfo) << result;
    if (s.exited()) {
      LOG(kInfo) << "Program returned exit code " << s.exit_status();
    } else if (s.stopped()) {
      LOG(kInfo) << "Program stopped by signal " << s.stop_signal();
    } else if (s.signaled()) {
      LOG(kInfo) << "Program received signal " << s.term_signal();
      if (s.dumped_core())
        LOG(kInfo) << "Program also dumped core";
    } else {
      LOG(kInfo) << "Program terminated for unknown reason";
    }
    LOG(kInfo) << "Restart count = " << (*i).restart_count;
    if (!(*i).done) {
      if ((*i).restart_count > 4) {
        LOG(kInfo) << "A process " << (*i).id << " is consistently failing. Stopping..." <<
        " Restart count = " << (*i).restart_count;
        return;
      }
      if (((*i).restart_count < 3)) {
        (*i).restart_count = (*i).restart_count + 1;
        RunProcess(id, true, false);
      } else {
        (*i).restart_count = (*i).restart_count + 1;
        RunProcess(id, true, true);
      }
    }
  }

  void ProcessManager::KillProcess(std::string id) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = true;
    // SetInstruction(id, ProcessInstruction::kTerminate);
  }

  void ProcessManager::StopProcess(std::string id) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = true;
    // SetInstruction(id, ProcessInstruction::kStop);
  }

  void ProcessManager::RestartProcess(std::string id) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = false;
    // SetInstruction(id, ProcessInstruction::kTerminate);
  }

  void ProcessManager::StartProcess(std::string id) {
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = false;
    (*i).restart_count = 0;
    LOG(kInfo) << "StartProcess: AddStatus. ID: " << id;
    // ProcessManagerStruct status;
    // status.instruction = ProcessInstruction::kRun;
    // AddStatus(id, status);
    boost::thread thd([=] { RunProcess(id, false, false); }); //NOLINT
    (*i).thread = std::move(thd);
  }

  void ProcessManager::LetProcessDie(std::string id) {
    LOG(kInfo) << "LetProcessDie: ID: " << id;
    auto i = FindProcess(id);
    if (i == processes_.end())
      return;
    (*i).done = true;
  }

  void ProcessManager::LetAllProcessesDie() {
    for (auto i(processes_.begin()); i != processes_.end(); ++i)
      (*i).done = true;
  }

  std::vector<ProcessInfo>::iterator ProcessManager::FindProcess(std::string id) {
    process_info_mutex_.lock();
    std::string id_to_find = id;
    auto it = std::find_if(processes_.begin(), processes_.end(), [=] (ProcessInfo &j) {
      return (j.id == id_to_find);
    });
    process_info_mutex_.unlock();
    return it;
  }

  void ProcessManager::WaitForProcesses() {
    for (auto &i : processes_) {
      while (!i.done) {}
      if (i.thread.joinable())
        i.thread.join();
    }
  }

  void ProcessManager::TerminateAll() {
    for (auto &i : processes_) {
      /*if (CheckInstruction(i.id) != ProcessInstruction::kTerminate) {
        i.done = true;
        LOG(kInfo) << "TerminateAll: SetInstruction to kTerminate";
        SetInstruction(i.id, ProcessInstruction::kTerminate);
      }*/
      if (i.thread.joinable())
        i.thread.join();
    }
    processes_.clear();
  }

  /*bool ProcessManager::AddStatus(std::string id, ProcessManagerStruct status) {
    // std::pair<TerminateVector*, std::size_t> t =
    //    shared_mem_.find<TerminateVector>("terminate_info");
    std::pair<StructMap*, std::size_t> t =
        shared_mem_.find<StructMap>("process_info");
    if (!(t.first)) {
      LOG(kError) << "AddStatus: failed to access IPC shared memory";
      return false;
    }
    (*t.first)[id] = status;
    LOG(kInfo) << "SIZE OF MAP!!!!!!!!!!!!: " << (*t.first).size();
    // LOG(kInfo) << "AddTerminateFlag: vector is now size " << (*t.first).size();
    LOG(kInfo) << "INSTRUCTION IN MAP!!!!!!!!!!!!: " << (*t.first)[id].instruction;
    LOG(kInfo) << "INSTRUCTION IN MAP WITH CHECK INSTRUCTION!!!!!!!!!!!!: " << CheckInstruction(id);
    return true;
  }

  bool ProcessManager::SetInstruction(std::string id, ProcessInstruction instruction) {
    std::pair<StructMap*, std::size_t> t =
        shared_mem_.find<StructMap>("process_info");
    if (!(t.first)) {
      LOG(kError) << "SetInstruction: failed to access IPC shared memory";
      return false;
    }
    if ((*t.first).count(id) == 0) {
        LOG(kInfo) << "SetInstruction: invalid process ID " << (*t.first).size();
      return false;
    }
    LOG(kInfo) << "SetInstruction: VALID process ID " << (*t.first).size();
    LOG(kInfo) << "SetInstruction: Instrucation set to " << instruction;
    (*t.first)[id].instruction = instruction;
    return true;
  }

  ProcessInstruction ProcessManager::CheckInstruction(std::string id) {
    std::pair<StructMap*, std::size_t> t =
        shared_mem_.find<StructMap>("process_info");
    if (!(t.first)) {
      LOG(kError) << "CheckInstruction: failed to access IPC shared memory";
      return ProcessInstruction::kInvalid;
    }
    if ((*t.first).count(id) == 0) {
      LOG(kInfo) << "CheckInstruction: invalid process ID " << id;
      return ProcessInstruction::kInvalid;
    }
    return (*t.first)[id].instruction;
  }*/
}  // namespace maidsafe

#ifdef __MSVC__
# pragma warning(pop)
#endif
