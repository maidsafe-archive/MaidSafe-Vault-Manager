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
//       maidsafe::Sleep(boost::posix_time::milliseconds(500));
//     if (check_finished)
//       return;
//     exit(0);
// }

void stop_handler() {
  LOG(kInfo) << "Process stopping, asked to stop by parent.";
  exit(0);
}

int main(int ac, char* av[]) {
  LOG(kInfo) << "Starting DUMMYprocess.";
  boost::thread thd;
  maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);
  maidsafe::priv::VaultController vc;
  po::options_description desc("Allowed options");
  desc.add_options()
      ("help", "produce help message")
      ("runtime", po::value<int>(), "Set runtime in seconds then crash")
      ("nocrash", "set no crash on runtime ended")
      ("vmid", po::value<std::string>(), "vault manager ID");
  try {
    po::variables_map vm;
    po::store(po::parse_command_line(ac, av, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        LOG(kInfo) << desc;
        return 1;
    }
    if (!vm.count("vmid")) {
      LOG(kInfo) << "DUMMYprocess: You must supply a vault manager ID";
      return 1;
    }
    std::string id = vm["vmid"].as<std::string>();
    LOG(kInfo) << "DUMMYprocess: Starting VaultController.";
    vc.Start(id.c_str(), [&] { stop_handler(); });  // NOLINT
    maidsafe::asymm::Keys keys;
    std::string account_name;
    vc.GetIdentity(&keys, &account_name);
    LOG(kInfo) << "DUMMYprocess: Identity: " << (keys.identity);
    LOG(kInfo) << "Validation Token: " << (keys.validation_token);
    std::string public_key_string;
    maidsafe::asymm::EncodePublicKey(keys.public_key, &public_key_string);
    std::string private_key_string;
    maidsafe::asymm::EncodePrivateKey(keys.private_key, &private_key_string);
    LOG(kInfo) << "Public Key: " << maidsafe::Base64Substr(public_key_string);
    LOG(kInfo) << "Private Key: " << maidsafe::Base64Substr(private_key_string);
    LOG(kInfo) << "Account name: " << account_name;
    if (vm.count("runtime")) {
      int runtime = vm["runtime"].as<int>();
        LOG(kInfo) << "Running for " << runtime << " seconds.";
        maidsafe::Sleep(boost::posix_time::seconds(runtime));
        if (vm.count("nocrash")) {
          check_finished = true;
          LOG(kInfo) << "DUMMYprocess: Process finishing normally. ";
          if (thd.joinable())
            thd.join();
          return 0;
        } else {
          return 1;
        }
    } else {
      while (true)
        maidsafe::Sleep(boost::posix_time::seconds(1));
    }
  } catch(std::exception& e)  {
    LOG(kError) << "Error: " << e.what();
    return 1;
  }
  return 0;
}
#ifdef __MSVC__
# pragma warning(pop)
#endif
