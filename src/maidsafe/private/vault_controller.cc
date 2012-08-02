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

#include "maidsafe/private/vault_controller.h"

#include <thread>
#include <chrono>
#include <iostream>

#ifdef __MSVC__
# pragma warning(push)
# pragma warning(disable: 4244 4250 4267)
#endif

#include "boost/process.hpp"
#include "boost/array.hpp"

#ifdef __MSVC__
# pragma warning(pop)
#endif

#include "maidsafe/private/vault_manager.h"
#include "maidsafe/private/vault_identity_info_pb.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace bai = boost::asio::ip;

namespace maidsafe {

namespace priv {

VaultController::VaultController() : process_id_(),
                                     port_(0),
                                     thread_(),
                                     asio_service_(new AsioService(10)),
                                     check_finished_(false),
                                     keys_(),
                                     account_name_(),
                                     info_received_(false),
                                     mutex_(),
                                     cond_var_(),
                                     started_(false),
                                     shutdown_mutex_(),
                                     shutdown_cond_var_(),
                                     shutdown_confirmed_(),
                                     stop_callback_() {
  asio_service_->Start();
}

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
      Sleep(boost::posix_time::milliseconds(500));
      instruction = CheckInstruction(static_cast<int32_t>(id));
    }
    if (check_finished_)
      return;
    if (instruction == ProcessInstruction::kStop)
      stop_callback();
    else if (instruction == ProcessInstruction::kTerminate)
      exit(0);
}*/

void VaultController::ReceiveKeys() {
  LOG(kInfo) << "VaultController: ReceiveKeys";
  std::string full_request;
  Endpoint endpoint(boost::asio::ip::address_v4::loopback(), port_);
  LOG(kInfo) << "ReceiveKeys: sending keys request to port " << port_;
  int message_type(static_cast<int>(VaultManagerMessageType::kIdentityInfoRequestFromVault));
  maidsafe::priv::VaultIdentityRequest request;
  request.set_vmid(process_id_);
  std::shared_ptr<TcpTransport> transport;
  std::shared_ptr<MessageHandler> message_handler;
  ResetTransport(transport, message_handler);
  full_request = message_handler->MakeSerialisedWrapperMessage(message_type,
                                                                request.SerializeAsString());
  LOG(kInfo) << "ReceiveKeys: Sending request for vault identity info to port" << endpoint.port;
  transport->Send(full_request, endpoint, boost::posix_time::milliseconds(1000));
}

void VaultController::ReceiveKeysCallback(const std::string& serialised_info,
                                          const Info& /*sender_info*/,
                                          std::string* /*response*/) {
  VaultIdentityInfo info;
  info.ParseFromString(serialised_info);
  boost::mutex::scoped_lock lock(mutex_);
  if (!maidsafe::rsa::ParseKeys(info.keys(), keys_)) {
    LOG(kError) << "ReceiveKeysCallback: failed to parse keys. ";
    info_received_ = false;
    return;
  } else {
    account_name_ = info.account_name();
    if (account_name_.empty()) {
      LOG(kError) << "ReceiveKeysCallback: account name is empty. ";
      info_received_ = false;
      return;
    }
    info_received_ = true;
    cond_var_.notify_all();
  }
}

void VaultController::ListenForShutdown() {
  std::string full_request;
  Endpoint endpoint(boost::asio::ip::address_v4::loopback(), port_);
  LOG(kInfo) << "ListenForShutdown: sending shutdown request to port " << port_;
  int message_type(static_cast<int>(VaultManagerMessageType::kShutdownRequestFromVault));
  maidsafe::priv::VaultShutdownRequest request;
  request.set_vmid(process_id_);
  std::shared_ptr<TcpTransport> transport;
  std::shared_ptr<MessageHandler> message_handler;
  ResetTransport(transport, message_handler);
  full_request = message_handler->MakeSerialisedWrapperMessage(message_type,
                                                                request.SerializeAsString());
  for (;;) {
    boost::mutex::scoped_lock lock(shutdown_mutex_);
    shutdown_cond_var_.timed_wait(lock, boost::posix_time::seconds(2),
                                  [&] { return shutdown_confirmed_; });  // NOLINT
    if (shutdown_confirmed_) {
      return;
    } else {
      lock.unlock();
      transport->Send(full_request, endpoint, boost::posix_time::milliseconds(1000));
    }
  }
}

void VaultController::ListenForShutdownCallback(const std::string& serialised_response,
                                                const Info& /*sender_info*/,
                                                std::string* /*response*/) {
  LOG(kInfo) << "ListenForShutdownCallback";
  VaultShutdownResponse response;
  if (response.ParseFromString(serialised_response)) {
    if (response.shutdown()) {
      boost::mutex::scoped_lock lock(shutdown_mutex_);
      shutdown_confirmed_ = true;
      LOG(kInfo) << "ListenForShutdownCallback: Shutdown confirmation received";
      shutdown_cond_var_.notify_one();
      lock.unlock();
      stop_callback_();
    }
  }
}

void VaultController::HandleIncomingMessage(const int& type, const std::string& payload,
                                              const Info& info, std::string* response,
                                              std::shared_ptr<TcpTransport> /*transport*/,
                                              std::shared_ptr<MessageHandler>
                                              /*message_handler*/) {
  LOG(kInfo) << "VaultController: HandleIncomingMessage";
  if (info.endpoint.ip.to_string() != "127.0.0.1") {
    LOG(kError) << "HandleIncomingMessage: message is not of local origin.";
    return;
  }
  VaultManagerMessageType message_type = boost::numeric_cast<VaultManagerMessageType>(type);
  switch (message_type) {
    case VaultManagerMessageType::kIdentityInfoToVault:
      LOG(kInfo) << "kIdentityInfoToVault";
      ReceiveKeysCallback(payload, info, response);
      break;
    case VaultManagerMessageType::kShutdownResponseToVault:
      LOG(kInfo) << "kShutdownResponseToVault";
      ListenForShutdownCallback(payload, info, response);
      break;
    default:
      LOG(kInfo) << "Incorrect message type";
  }
}

void VaultController::ResetTransport(std::shared_ptr<TcpTransport>& transport,
                                      std::shared_ptr<MessageHandler>& message_handler) {
  transport.reset(new TcpTransport(asio_service_->service()));
  message_handler.reset(new MessageHandler());
  transport->on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                        message_handler.get(), _1, _2, _3, _4));
  transport->on_error()->connect(boost::bind(&MessageHandler::OnError,
                                              message_handler.get(), _1, _2));
    message_handler->SetCallback(
        boost::bind(&maidsafe::priv::VaultController::HandleIncomingMessage, this, _1, _2, _3, _4,
                    transport, message_handler));
}

bool VaultController::Start(std::string vmid_string,
                            std::function<void()> stop_callback) {
  stop_callback_ = stop_callback;
  try {
    if (vmid_string == "") {
      LOG(kInfo) << " VaultController: Start: You must supply a process id";
      return false;
    }
    boost::char_separator<char> sep("-");
    boost::tokenizer<boost::char_separator<char>> tok(vmid_string, sep);
    int size(0);
    for (auto it(tok.begin()); it != tok.end(); ++it, ++size) {}
    if (size != 2) {
      LOG(kError) << " VaultController: Invalid Vault Manager ID";
    }
    auto it(tok.begin());
    if ((*it).length() > 0)
      process_id_ = (*it);
    else
      LOG(kError) << " VaultController: Invalid Vault Manager ID";
    ++it;
    if ((*it).length() > 0)
      port_ = boost::lexical_cast<uint16_t>(*it);
    else
      LOG(kError) << " VaultController: Invalid Vault Manager ID";
    if (port_ != 0) {
      thread_ = boost::thread([=] { ReceiveKeys();
                                    ListenForShutdown();
      });
    }
  } catch(std::exception& e)  {
    LOG(kError) << "VaultController: Start: Error receiving keys" << e.what();
    return false;
  }
  started_ = true;
  return true;
}

bool VaultController::GetIdentity(maidsafe::rsa::Keys* keys, std::string* account_name) {
  if (!started_)
    return false;
  if (port_ == 0)
    return false;
  boost::mutex::scoped_lock lock(mutex_);
  if (cond_var_.timed_wait(lock,
                            boost::posix_time::seconds(10),
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
