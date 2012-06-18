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

#include <string>
#include <vector>
#include <utility>
#include <thread>
#include <chrono>
#include <algorithm>
#include <boost/process.hpp>
#include <boost/filesystem.hpp>

#include "maidsafe/private/process_manager.h"

namespace maidsafe {

namespace bp = boost::process;

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

ProcessManager::ProcessManager() :
  processes_(),
  process_count_(0),
  done_(false) {}

ProcessManager::~ProcessManager() {
  TerminateAll();
}

int ProcessManager::AddProcess(Process process) {
  ProcessInfo info;
  info.process = process;
  info.id = ++process_id_;
  info.done = false;
//  std::thread thd([=] { RunProcess(process_id_); });
//  info.thread = std::move(thd);
  processes_.push_back(std::move(info));
  return process_id_;
}

int32_t ProcessManager::NumberOfProcesses() {
  return processes_.size();
}


int32_t ProcessManager::NumberOfLiveProcesses() {
  int32_t count(0);
  for (auto &i : processes_) {
    if(!i.done && i.thread.joinable())
      ++count;
  }
  return count;
}

int32_t ProcessManager::NumberOfSleepingProcesses() {
  int32_t count(0);
  for (auto &i : processes_) {
    if(!i.done)
      ++count;
  }
  return count;
}

void ProcessManager::RunProcess(int32_t id) {
  auto i = FindProcess(id);
  if (i == processes_.end())
    return;
  bp::context ctx;
  ctx.environment = bp::self::get_environment();
  bp::child c = bp::launch((*i).process.ProcessName(), (*i).process.Args(), ctx);
  (*i).child = c;
  c.wait();
  if (! (*i).done)
    RunProcess(id);
}

void ProcessManager::KillProcess(int32_t id) {
  auto i = FindProcess(id);
  if (i == processes_.end())
    return;
  (*i).done = true;
  (*i).child.terminate(true);
}

void ProcessManager::RestartProcess(int32_t id) {
  auto i = FindProcess(id);
  if (i == processes_.end())
    return;
  (*i).done = false;
 // (*i).child.terminate(true);
  std::thread thd([=] { RunProcess(id); });
  (*i).thread = std::move(thd);
}

void ProcessManager::StartProcess(int32_t id) {
  auto i = FindProcess(id);
  if (i == processes_.end())
    return;
  (*i).done = false;
  std::thread thd([=] { RunProcess(id); });
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
  return std::find_if(processes_.begin(), processes_.end(),[=] (ProcessInfo &j) {
    return (j.id == id_to_find);
  });
}

void ProcessManager::TerminateAll() {
  for (auto &i : processes_) {
    i.done = true;
   // i.child.terminate();
   i.thread.join();
  }
  processes_.clear();
}

}  // namespace maidsafe
