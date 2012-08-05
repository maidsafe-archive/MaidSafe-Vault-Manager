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

#ifndef MAIDSAFE_PRIVATE_PROCESS_MANAGER_H_
#define MAIDSAFE_PRIVATE_PROCESS_MANAGER_H_

#include <mutex>
#include <cstdint>
#include <string>
#include <vector>

#include "boost/thread/thread.hpp"

namespace maidsafe {

namespace priv {

/*enum class ProcessStatus {
  Running,
  Stopped,
  Crashed
};

enum ProcessInstruction {
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
  Process() : args_(), process_name_() {}
  bool SetProcessName(std::string process_name, std::string parent_path = "");
  void AddArgument(std::string argument);
  std::string ProcessName() const;
  std::vector<std::string> Args() const;
 private:
  std::vector<std::string> args_;
  std::string process_name_;
};

struct ProcessInfo {
  ProcessInfo() : process(), thread(), id(), port(), restart_count(0), done(false) {}
  ProcessInfo(ProcessInfo&& other);
  ProcessInfo& operator=(ProcessInfo&& other);
  Process process;
  boost::thread thread;
  std::string id;
  uint32_t port;
  int32_t restart_count;
  bool done;
};

class ProcessManager {
 public:
  ProcessManager();
  ~ProcessManager();
  std::string AddProcess(Process process, uint16_t port);
  int32_t NumberOfProcesses() const;
  int32_t NumberOfLiveProcesses() const;
  int32_t NumberOfSleepingProcesses() const;
  void StartProcess(std::string id);
  void LetProcessDie(std::string id);
  void LetAllProcessesDie();
  void WaitForProcesses();
  void KillProcess(std::string id);
  void StopProcess(std::string id);
  void RestartProcess(std::string id);

 private:
  ProcessManager(const ProcessManager&);
  ProcessManager &operator=(const ProcessManager&);
  std::vector<ProcessInfo>::iterator FindProcess(std::string id);
  void RunProcess(std::string id, bool restart, bool logging);
  void TerminateAll();

  std::vector<ProcessInfo> processes_;
  mutable std::mutex mutex_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_PROCESS_MANAGER_H_
