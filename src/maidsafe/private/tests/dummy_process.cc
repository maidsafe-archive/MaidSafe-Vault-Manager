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

#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/containers/vector.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/program_options.hpp>
#include <thread>
#include <chrono>
#include <iostream>

#include "maidsafe/common/log.h"
#include "maidsafe/private/vault_controller.h"
#include "maidsafe/common/utils.h"

namespace po = boost::program_options;
namespace bi = boost::interprocess;

enum class TerminateStatus {
  kTerminate = 1,
  kNoTerminate = 2
};

enum ProcessInstruction {
  kRun = 1,
  kStop = 2,
  kTerminate = 3,
  kInvalid = 4
};

struct ProcessManagerStruct {
  ProcessInstruction instruction;
};

  typedef bi::allocator<TerminateStatus,
      bi::managed_shared_memory::segment_manager> TerminateAlloc;
  typedef bi::vector<TerminateStatus, TerminateAlloc> TerminateVector;

  static bool check_finished(false);

// bool CheckTerminateFlag(int32_t id, bi::managed_shared_memory& shared_mem) {
//   std::pair<TerminateVector*, std::size_t> t =
//       shared_mem.find<TerminateVector>("terminate_info");
//   size_t size(0);
//   if (t.first) {
//     size = (*t.first).size();
//   } else {
//     std::cout << "CheckTerminateFlag: failed to access IPC shared memory";
//     return false;
//   }
//   if (size <= static_cast<size_t>(id - 1) || id - 1 < 0) {
//     std::cout << "CheckTerminateFlag: given process id is invalid or outwith range of "
//               << "terminate vector";
//     return false;
//   }
//   if ((*t.first).at(id - 1) == TerminateStatus::kTerminate) {
//     std::cout << "Process terminating. ";
//     return true;
//   }
//   return false;
// }
//
// void ListenForTerminate(std::string shared_mem_name, int id) {
//     bi::managed_shared_memory shared_mem(bi::open_or_create,
//                                                           shared_mem_name.c_str(),
//                                                           1024);
//     while (!CheckTerminateFlag(static_cast<int32_t>(id), shared_mem) && !check_finished)
//       boost::this_thread::sleep(boost::posix_time::milliseconds(500));
//     if (check_finished)
//       return;
//     exit(0);
// }

void stop_handler() {
  std::cout << "Process stopping, asked to stop by parent." << std::endl;
  exit(0);
}

int main(int ac, char* av[]) {
  std::thread thd;
  maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);
  maidsafe::priv::VaultController vc;
  po::options_description desc("Allowed options");
  desc.add_options()
      ("help", "produce help message")
      ("runtime", po::value<int>(), "Set runtime in seconds then crash")
      ("nocrash", "set no crash on runtime ended")
      ("pid", po::value<std::string>(), "process id")
      ("randomstuff", po::value<std::string>(), "random stuff");
  try {
    po::variables_map vm;
    po::store(po::parse_command_line(ac, av, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << "\n";
        return 1;
    }
    if (!vm.count("pid")) {
      LOG(kInfo) << " main:You must supply a process id";
      return 1;

      std::string id = vm["pid"].as<std::string>();
      vc.Start(id.c_str(), [&] { stop_handler(); });  // NOLINT
    }
    if (vm.count("runtime")) {
      int runtime = vm["runtime"].as<int>();
        std::cout << "Running for " << runtime << " seconds. \n";
        std::this_thread::sleep_for(std::chrono::seconds(runtime));
        if (vm.count("nocrash")) {
          check_finished = true;
          std::cout << "Process finishing normally. ";
          if (thd.joinable())
            thd.join();
          return 0;
        } else {
          return 1;
        }
    } else {
      while (true)
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  } catch(std::exception& e)  {
    std::cout << "WE'RE DEFINITELY HERE " << e.what() << " WE'RE HERE\n";
    return 1;
  }
  return 0;
}

/*#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/thread.hpp>
#include <string>
#include <iostream>

namespace bi = boost::interprocess;

struct Struct {
  int32_t integer;
};

int main(int ac, char* av[]) {
  typedef boost::interprocess::allocator<std::pair<const int32_t, Struct>,
    boost::interprocess::managed_shared_memory::segment_manager> StructAlloc;
  typedef boost::interprocess::map<int32_t, Struct, std::less<int32_t>, StructAlloc> StructMap;
  std::string shared_mem_name("hello");

  boost::this_thread::sleep(boost::posix_time::milliseconds(2000));

  boost::interprocess::managed_shared_memory shared_mem(boost::interprocess::open_or_create, shared_mem_name.c_str(), 4096);
  std::pair<StructMap*, std::size_t> map_pair(shared_mem.find<StructMap>("struct_map"));
  for (auto it((map_pair.first)->begin()); it != (map_pair.first)->end(); ++it)
    std::cout << "KEY: " << (*it).first << " VALUE: " << (*it).second.integer << std::endl;
  for (int i(1); i < 11; ++i)
    std::cout << "KEY " << i << " HAS " << (*map_pair.first).count(i) << " VALUE(S)" << std::endl;
  return 0;
}*/
