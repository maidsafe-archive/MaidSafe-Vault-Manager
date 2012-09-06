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

#ifndef MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_PROCESS_MANAGER_H_
#define MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_PROCESS_MANAGER_H_

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

namespace priv {

namespace process_management {

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
  void StartProcess(const ProcessIndex& index);
  void LetProcessDie(const ProcessIndex& index);
  void LetAllProcessesDie();
  void WaitForProcesses();
  void KillProcess(const ProcessIndex& index);
  void StopProcess(const ProcessIndex& index);
  void RestartProcess(const ProcessIndex& index);
  ProcessStatus GetProcessStatus(const ProcessIndex& index);
  bool WaitForProcessToStop(const ProcessIndex& index);
  static ProcessIndex kInvalidIndex() { return std::numeric_limits<ProcessIndex>::max(); }

 private:
  struct ProcessInfo {
    ProcessInfo() : process(),
                    thread(),
                    index(0),
                    port(0),
                    restart_count(0),
                    done(false),
                    status(ProcessStatus::kStopped),
#ifdef MAIDSAFE_WIN32
                    child(PROCESS_INFORMATION()) {}
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
  ProcessManager &operator=(const ProcessManager&);
  std::vector<ProcessInfo>::iterator FindProcess(const ProcessIndex& index);
  void RunProcess(const ProcessIndex& index, bool restart, bool logging);
  void TerminateAll();
  bool SetProcessStatus(const ProcessIndex& index, const ProcessStatus& status);

  std::vector<ProcessInfo> processes_;
  ProcessIndex current_max_id_;
  mutable std::mutex mutex_;
  std::condition_variable cond_var_;
};

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_PROCESS_MANAGER_H_
