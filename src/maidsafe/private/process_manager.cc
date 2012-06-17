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

#include <boost/process.hpp>
#include <boost/filesystem.hpp>

#include "maidsafe/private/process_manager.h"

namespace bp = boost::process;

bool Process::SetProcessName(std::string process_name) {
  std::string path_string(boost::filesystem::current_path().string());
  boost::system::error_condition ec;
  boost::filesystem3::exists(process_name, ec);
  if (!ec)
    return false;
  std::string exec = bp::find_executable_in_path(process_name, path_string);
  process_name_ = process_name;
  return true;
}

void Process::AddArgument(std::string argument) {
  args_.push_back(argument);
}

std::string Process::ProcessName() {
  return process_name_;
}

std::vector<std::string> Process::Args() {
  return args_;
}



bool ProcessManager::RunAll() {
  for (auto &i, processes_) {
  #ifdef MAIDSAFE_WIN32
    bp::win32_context ctx;
    ctx.environment = bp::self::get_environment();
    bp::child c = bp::win32_launch(i.ProcessName(), i.Args(), ctx);
  #else
    bp::posix_context ctx;
    ctx.environment = bp::self::get_environment();
    bp::child c = bp::posix_launch(i.ProcessName(), i.Args(), ctx);
  #endif
    processes_[i] = c;
  }
}

void ProcessManager::MonitorAll() {
  for (auto &i, processes_) {
    if (processes_.second.get_stderr().valid()) {
    #ifdef MAIDSAFE_WIN32
      bp::win32_context ctx;
      ctx.environment = bp::self::get_environment();
      processes_.second = bp::win32_launch(i.ProcessName(), i.Args(), ctx);
    #else
      bp::posix_context ctx;
      ctx.environment = bp::self::get_environment();
      processes_.second = bp::posix_launch(i.ProcessName(), i.Args(), ctx);
    #endif
    }
  }
}



int launch(const std::string& exec, std::vector<std::string> args) {



#ifdef MAIDSAFE_WIN32
  bp::win32_status s = c.wait();
#else
  bp::posix_status s = c.wait();
#endif
  if (s.exited())
    std::cout << s.exit_status() << std::endl;
  if (s.signaled())
    std::cout << s.term_signal() << std::endl;
  return s.exit_status();
}

void manage_process(const std::string& exec, std::vector<std::string> args, int i) {
  int result(launch(exec, args));
  std::cout << "Dummy process " << i << " exits with result " << result << std::endl;
  while (result != 0) {
    std::cout << "Dummy process " << i << " crashed, restarting..." << std::endl;
    args.push_back("--nocrash");
    result = launch(exec, args);
  }
  std::cout << "Dummy process " << i << " Exited successfully" << std::endl;
}

int main()
{
  std::string path_string(boost::filesystem::current_path().string());
  std::string exec = bp::find_executable_in_path("DUMMYprocess", path_string);
  for (int i(0); i < 5; ++i) {
    std::vector<std::string> args;
    args.push_back("DUMMYprocess");
    if(i % 2 == 0) {
      args.push_back("--runtime");
      args.push_back("2");
    }
    manage_process(exec, args, i);
  }
  return 0;
}

