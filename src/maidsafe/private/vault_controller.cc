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
#include <boost/interprocess/containers/map.hpp>
#include <boost/interprocess/allocators/allocator.hpp>
#include <boost/interprocess/sync/named_mutex.hpp>
#include <boost/interprocess/sync/named_condition.hpp>
#include <boost/program_options.hpp>
#include <thread>
#include <chrono>
#include <iostream>

#include "maidsafe/private/vault_controller.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace maidsafe {
namespace priv {

  namespace bi = boost::interprocess;
  /*typedef bi::allocator<TerminateStatus,
      bi::managed_shared_memory::segment_manager> TerminateAlloc;
  typedef bi::vector<TerminateStatus, TerminateAlloc> TerminateVector;*/
  /*typedef bi::allocator<KeysStatus,
      bi::managed_shared_memory::segment_manager> KeysAlloc;
  typedef bi::vector<TerminateStatus, KeysAlloc> KeysVector;*/
  typedef bi::allocator<std::pair<int32_t, ProcessManagerStruct>,
      bi::managed_shared_memory::segment_manager> StructAlloc;
  typedef bi::map<int32_t, ProcessManagerStruct, std::less<int32_t>, StructAlloc> StructMap;


  VaultController::VaultController() : process_id_(),
                                      shared_mem_name_(),
                                      shared_mem_(),
                                      check_finished_(false),
                                      thd() {}

  VaultController::~VaultController() {}

  /*bool VaultController::CheckTerminateFlag(int32_t id, bi::managed_shared_memory& shared_mem) {
    std::pair<TerminateVector*, std::size_t> t = shared_mem.find<TerminateVector>("terminate_info");
    size_t size(0);
    if (t.first) {
      size = (*t.first).size();
    } else {
      std::cout << "CheckTerminateFlag: failed to access IPC shared memory";
      return false;
    }
    if (size <= static_cast<size_t>(id - 1) || id - 1 < 0) {
      std::cout << "CheckTerminateFlag: given process id is invalid or outwith range of "
                << "terminate vector";
      return false;
    }
    if ((*t.first).at(id - 1) == TerminateStatus::kTerminate) {
      std::cout << "Process terminating. ";
      return true;
    }
    return false;
  }*/

  ProcessInstruction VaultController::CheckInstruction(const int32_t& id) {
    std::pair<StructMap*, std::size_t> t =
        shared_mem_.find<StructMap>("process_info");
    if (!(t.first)) {
      LOG(kError) << "CheckInstruction: failed to access IPC shared memory";
      return ProcessInstruction::kInvalid;
    }
    for (auto it((*t.first).begin()); it != (*t.first).end(); ++it)
      LOG(kInfo) << "KEY: " << (*it).first << " VALUE: " << (*it).second.instruction;

    auto it((*t.first).begin());
    for (; it != (*t.first).end(); ++it) {
      // LOG(kInfo) << "KEY: " << (*it).first << " VALUE: " << (*it).second.instruction;
      if ((*it).first == id) {
        LOG(kInfo) << "FOUND KEY!!!! " << (*it).first << ", " << id;
        break;
      }
    }
    LOG(kInfo) << "MAP SIZE FROM CLIENT!!!!" << (*t.first).size();
    LOG(kInfo) << "REAL INSTRUCTION FROM CLIENT!!!!" << (*it).second.instruction;
    if (it == (*t.first).end()) {
      LOG(kInfo) << "CheckInstruction: invalid process ID " << id;
      return ProcessInstruction::kInvalid;
    }
    /*if ((*t.first).count(id) == 0) {
      LOG(kInfo) << "CheckInstruction: invalid process ID " << id;
      return ProcessInstruction::kInvalid;
    }
    return (*t.first)[id].instruction;*/
    return (*it).second.instruction;
  }

  void VaultController::ListenForStopTerminate(std::string shared_mem_name, int32_t id,
                                               std::function<void()> stop_callback) {
      shared_mem_ = bi::managed_shared_memory(bi::open_or_create,  shared_mem_name.c_str(), 4096);
      ProcessInstruction instruction = CheckInstruction(id);
      while (instruction == ProcessInstruction::kRun && !check_finished_) {
        boost::this_thread::sleep(boost::posix_time::milliseconds(500));
        instruction = CheckInstruction(static_cast<int32_t>(id));
      }
      if (check_finished_)
        return;
      if (instruction == ProcessInstruction::kStop)
        stop_callback();
      else if (instruction == ProcessInstruction::kTerminate)
        exit(0);
  }

  bool VaultController::Start(std::string shared_mem_name, std::string pid_string,
                              std::function<void()> stop_callback) {
    try {
      if (shared_mem_name != "") {
        if (pid_string == "") {
          LOG(kInfo) << " VaultController: To use shared memory, you must supply a process id";
          return 1;
        }
        int pid = boost::lexical_cast<int32_t>(pid_string);
        thd = boost::thread([=] {
                                   ListenForStopTerminate(shared_mem_name, pid, stop_callback);
                                });
      }
    } catch(std::exception& e)  {
      std::cout << e.what() << "\n";
      return false;
    }

    return true;
  }

  bool VaultController::GetKeys(std::string* /*keys*/) {
    /*std::pair<KeysVector*, std::size_t> t = shared_mem_.find<KeysVector>("keys_info");
    bi::named_mutex mtx(bi::open_or_create, "keys_mutex");
    bi::named_condition cnd(bi::open_or_create, "keys_cond");
    boost::interprocess::scoped_lock<bi::named_mutex> lock(mtx);
    size_t size(0);
    if (t.first) {
      size = (*t.first).size();
    } else {
      std::cout << "GetKeys: failed to access IPC shared memory";
      return false;
    }
    if (size <= static_cast<size_t>(process_id_ - 1) || process_id_ - 1 < 0) {
      std::cout << "GetKeys: given process id is invalid or outwith range of "
                << "keys vector";
      return false;
    }
    (*t.first) = KeysStatus::kNeedKeys;
    while ((*t.first) == KeysStatus::kNeedKeys) {
      cnd.wait(lock);
      cnd.notify_all();
    }*/
    return true;
  }
}  // namespace priv

}  // namespace maidsafe

