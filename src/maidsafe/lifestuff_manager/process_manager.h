/*  Copyright 2012 MaidSafe.net limited

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

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_PROCESS_MANAGER_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_PROCESS_MANAGER_H_

#include <mutex>
#include <condition_variable>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/thread/thread.hpp"

#include "boost/process/child.hpp"

namespace maidsafe {

namespace lifestuff_manager {

typedef uint32_t ProcessIndex;

enum class ProcessStatus {
  kRunning = 1,
  kStopped = 2,
  kCrashed = 3,
  kError = 4
};

/*enum ProcessInstruction {
  kRun = 1,
  kStop = 2,
  kTerminate = 3,
  kInvalid = 4
};

enum class TerminateStatus {
  kTerminate = 1,
  kNoTerminate = 2
};

enum class StopStatus {
  kStop = 1,
  kNoStop = 2
};


struct ProcessManagerStruct {
  ProcessInstruction instruction;
};*/

class Process {
 public:
  Process() : args_(), name_() {}
  bool SetExecutablePath(const boost::filesystem::path& executable_path);
  void AddArgument(const std::string& argument) { args_.push_back(argument); }
  std::string name() const { return name_; }
  std::vector<std::string> args() const { return args_; }

 private:
  std::vector<std::string> args_;
  std::string name_;
};

class ProcessManager {
 public:
  ProcessManager();
  ~ProcessManager();
  ProcessIndex AddProcess(Process process, uint16_t port);
  size_t NumberOfProcesses() const;
  size_t NumberOfLiveProcesses() const;
  size_t NumberOfSleepingProcesses() const;
  void StartProcess(ProcessIndex index);
  void LetProcessDie(ProcessIndex index);
  void LetAllProcessesDie();
  void WaitForProcesses();
  void KillProcess(ProcessIndex index);
  void StopProcess(ProcessIndex index);
  void RestartProcess(ProcessIndex index);
  ProcessStatus GetProcessStatus(ProcessIndex index);
  bool WaitForProcessToStop(ProcessIndex index);
  static ProcessIndex kInvalidIndex() { return std::numeric_limits<ProcessIndex>::max(); }

 private:
  struct ProcessInfo {
    ProcessInfo()
        : process(),
          thread(),
          index(0),
          port(0),
          restart_count(0),
          done(false),
          status(ProcessStatus::kStopped),
#ifdef MAIDSAFE_WIN32
          child(PROCESS_INFORMATION()) {
    }
#else
    child(0) {}
#endif
    ProcessInfo(ProcessInfo&& other);
    ProcessInfo& operator=(ProcessInfo&& other);
    Process process;
    boost::thread thread;
    ProcessIndex index;
    uint16_t port;
    int32_t restart_count;
    bool done;
    ProcessStatus status;
    boost::process::child child;
  };

  ProcessManager(const ProcessManager&);
  ProcessManager& operator=(const ProcessManager&);
  std::vector<ProcessInfo>::iterator FindProcess(ProcessIndex index);
  void RunProcess(ProcessIndex index, bool restart, bool logging);
  void TerminateAll();
  bool SetProcessStatus(ProcessIndex index, const ProcessStatus& status);

  std::vector<ProcessInfo> processes_;
  ProcessIndex current_max_id_;
  mutable std::mutex mutex_;
  std::condition_variable cond_var_;
};

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_PROCESS_MANAGER_H_
