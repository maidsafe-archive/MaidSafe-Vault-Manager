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
#include <boost/array.hpp>
#include <thread>
#include <chrono>
#include <iostream>

#include "maidsafe/private/vault_controller.h"
#include "maidsafe/private/vault_manager.h"
#include "maidsafe/private/vault_identity_info.pb.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace maidsafe {
namespace priv {



  VaultController::VaultController() : process_id_(),
                                      port_(0),
                                      thd(),
                                      io_service_(),
                                      resolver_(io_service_),
                                      query_("", ""),
                                      endpoint_iterator_(),
                                      socket_(io_service_),
                                      check_finished_(false),
                                      keys_(),
                                      account_name_(),
                                      info_received_(false),
                                      mutex_(),
                                      cond_var_(),
                                      transport_(io_service_),
                                      message_handler_() {}

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

//   ProcessInstruction VaultController::CheckInstruction(const int32_t& id) {
//     std::pair<StructMap*, std::size_t> t =
//         shared_mem_.find<StructMap>("process_info");
//     if (!(t.first)) {
//       LOG(kError) << "CheckInstruction: failed to access IPC shared memory";
//       return ProcessInstruction::kInvalid;
//     }
//     for (auto it((*t.first).begin()); it != (*t.first).end(); ++it)
//       LOG(kInfo) << "KEY: " << (*it).first << " VALUE: " << (*it).second.instruction;
//
//     auto it((*t.first).begin());
//     for (; it != (*t.first).end(); ++it) {
//       // LOG(kInfo) << "KEY: " << (*it).first << " VALUE: " << (*it).second.instruction;
//       if ((*it).first == id) {
//         LOG(kInfo) << "FOUND KEY!!!! " << (*it).first << ", " << id;
//         break;
//       }
//     }
//     LOG(kInfo) << "MAP SIZE FROM CLIENT!!!!" << (*t.first).size();
//     LOG(kInfo) << "REAL INSTRUCTION FROM CLIENT!!!!" << (*it).second.instruction;
//     if (it == (*t.first).end()) {
//       LOG(kInfo) << "CheckInstruction: invalid process ID " << id;
//       return ProcessInstruction::kInvalid;
//     }
//     /*if ((*t.first).count(id) == 0) {
//       LOG(kInfo) << "CheckInstruction: invalid process ID " << id;
//       return ProcessInstruction::kInvalid;
//     }
//     return (*t.first)[id].instruction;*/
//     return (*it).second.instruction;
//   }

  /*void VaultController::ListenForStopTerminate(std::string shared_mem_name, int32_t id,
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
  }*/

  void VaultController::PrintResult(std::string serv,
    boost::asio::ip::tcp::resolver::iterator iter,
    const boost::system::error_code& ec) {
    if (ec)
        std::cout << "service: '" << serv << "' FAIL: " << ec.message() << "\n";
    else
    {
        std::cout << "service: '" << serv << "' OK\n";
        std::cout << "endpoint: " << iter->endpoint() << "\n";
    }
  }

  void VaultController::ReceiveKeys() {
     transport_.on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                            &message_handler_, _1, _2, _3, _4));
     message_handler_.SetCallback(
          boost::bind(&maidsafe::priv::VaultController::ReceiveKeysCallback, this, _1, _2, _3));
    std::string full_request;
    maidsafe::priv::VaultIdentityRequest request;
    Endpoint endpoint("127.0.0.1", port_);
    {
      boost::mutex::scoped_lock lock(mutex_);
      std::cout << "ReceiveKeys, sending request for vault identity info" << std::endl;
      int message_type(static_cast<int>(VaultManagerMessageType::kIdentityInfoRequestFromVault));
      request.set_pid(process_id_);
      full_request = message_handler_.MakeSerialisedWrapperMessage(message_type,
                                                                  request.SerializeAsString());
    }
    transport_.Send(full_request, endpoint, boost::posix_time::milliseconds(50));
  }

  void VaultController::ReceiveKeysCallback(const int& type, const std::string& serialised_info,
                                            const Info& /*sender_info*/) {
    boost::mutex::scoped_lock lock(mutex_);
    if (type != static_cast<int>(VaultManagerMessageType::kIdentityInfoToVault)) {
      std::cout << "ReceiveKeysCallback: response message is of incorrect type." << std::endl;
      return;
    }
    VaultIdentityInfo info;
    info.ParseFromString(serialised_info);
    if (!maidsafe::rsa::ParseKeys(info.keys(), keys_)) {
      std::cout << "ReceiveKeysCallback: failed to parse keys. " << std::endl;
      info_received_ = false;
      return;
    } else {
      account_name_ = info.account_name();
      if (account_name_ == "") {
        std::cout << "ReceiveKeysCallback: account name is empty. " << std::endl;
        info_received_ = false;
        return;
      }
      info_received_ = true;
      cond_var_.notify_all();
    }
    std::cout << "KEYS RECEIVED: " << std::endl;
    std::string public_key_string, private_key_string;
    rsa::EncodePublicKey(keys_.public_key, &public_key_string);
    std::cout << "PUBLIC KEY" << public_key_string << std::endl;
    rsa::EncodePrivateKey(keys_.private_key, &private_key_string);
    std::cout << "PRIVATE KEY" << private_key_string << std::endl;
    std::cout << "Message received from manager: " << serialised_info << std::endl;
  }

  bool VaultController::Start(std::string pid_string,
                              std::function<void()> /*stop_callback*/) {
    std::cout << "IN VaultController Start" << std::endl;
    try {
      if (pid_string == "") {
        LOG(kInfo) << " VaultController: you must supply a process id";
        return 1;
      }
      boost::char_separator<char> sep("-");
      boost::tokenizer<boost::char_separator<char>> tok(pid_string, sep);
      auto it(tok.begin());
      process_id_ = (*it);
      ++it;
      port_ = boost::lexical_cast<uint16_t>(*it);
      std::cout << "PORT: " << port_ << std::endl;
      thd = boost::thread([=] {
                                ReceiveKeys();
                                  /*ListenForStopTerminate(shared_mem_name, pid, stop_callback);*/
                              });
    } catch(std::exception& e)  {
      std::cout << e.what() << "\n";
      return false;
    }
    if (thd.joinable())
      thd.join();
    return true;
  }

  bool VaultController::GetIdentity(maidsafe::rsa::Keys* keys, std::string* account_name) {
    boost::mutex::scoped_lock lock(mutex_);
    if (cond_var_.timed_wait(lock,
                             boost::posix_time::seconds(3),
                             [&]()->bool { return info_received_; })) {  // NOLINT (Philip)
      keys->private_key = keys_.private_key;
      keys->public_key = keys_.public_key;
      keys->identity = keys_.identity;
      keys->validation_token = keys_.validation_token;
      *account_name = account_name_;
      return true;
    }
    return false;
  }
}  // namespace priv

}  // namespace maidsafe

