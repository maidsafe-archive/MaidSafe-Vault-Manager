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

#include "maidsafe/private/vault_controller.h"

#include <iterator>

#include "maidsafe/common/log.h"

#include "maidsafe/private/tcp_transport.h"
#include "maidsafe/private/message_handler.h"
#include "maidsafe/private/vault_manager.h"
#include "maidsafe/private/vault_identity_info_pb.h"


namespace maidsafe {

namespace priv {

VaultController::VaultController() : process_id_(),
                                     port_(0),
                                     thread_(),
                                     asio_service_(2),
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
  asio_service_.Start();
}

VaultController::~VaultController() {}

void VaultController::ReceiveKeys() {
  int message_type(static_cast<int>(VaultManagerMessageType::kIdentityInfoRequestFromVault));
  maidsafe::priv::VaultIdentityRequest request;
  request.set_vault_manager_id(process_id_);
  std::shared_ptr<TcpTransport> transport;
  std::shared_ptr<MessageHandler> message_handler;
  ResetTransport(transport, message_handler);
  std::string full_request =
      message_handler->MakeSerialisedWrapperMessage(message_type, request.SerializeAsString());
  Endpoint endpoint(boost::asio::ip::address_v4::loopback(), port_);
  LOG(kInfo) << "ReceiveKeys: Sending request for vault identity info to port" << endpoint.port;
  transport->Send(full_request, endpoint, boost::posix_time::seconds(1));
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
  }

  account_name_ = info.account_name();
  if (account_name_.empty()) {
    LOG(kError) << "ReceiveKeysCallback: account name is empty. ";
    info_received_ = false;
    return;
  }

  info_received_ = true;
  cond_var_.notify_all();
}

void VaultController::ListenForShutdown() {
  LOG(kInfo) << "ListenForShutdown: sending shutdown request to port " << port_;
  maidsafe::priv::VaultShutdownRequest request;
  request.set_vault_manager_id(process_id_);
  std::shared_ptr<TcpTransport> transport;
  std::shared_ptr<MessageHandler> message_handler;
  ResetTransport(transport, message_handler);
  int message_type(static_cast<int>(VaultManagerMessageType::kShutdownRequestFromVault));
  std::string full_request =
      message_handler->MakeSerialisedWrapperMessage(message_type, request.SerializeAsString());
  for (;;) {
    boost::mutex::scoped_lock lock(shutdown_mutex_);
    shutdown_cond_var_.timed_wait(lock, boost::posix_time::seconds(2),
                                  [&] { return shutdown_confirmed_; });  // NOLINT
    if (shutdown_confirmed_) {
      return;
    } else {
      Endpoint endpoint(boost::asio::ip::address_v4::loopback(), port_);
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
    }
    stop_callback_();
  }
}

void VaultController::HandleIncomingMessage(const int& type,
                                            const std::string& payload,
                                            const Info& info,
                                            std::string* response,
                                            std::shared_ptr<TcpTransport> /*transport*/,
                                            std::shared_ptr<MessageHandler> /*message_handler*/) {
  LOG(kInfo) << "VaultController: HandleIncomingMessage";
  if (!info.endpoint.ip.is_loopback()) {
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
  transport.reset(new TcpTransport(asio_service_.service()));
  message_handler.reset(new MessageHandler());
  transport->on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                        message_handler.get(), _1, _2, _3, _4));
  transport->on_error()->connect(boost::bind(&MessageHandler::OnError,
                                              message_handler.get(), _1, _2));
    message_handler->SetCallback(
        boost::bind(&maidsafe::priv::VaultController::HandleIncomingMessage, this, _1, _2, _3, _4,
                    transport, message_handler));
}

bool VaultController::Start(const std::string& vault_manager_id,
                            std::function<void()> stop_callback) {
  stop_callback_ = stop_callback;
  try {
    if (vault_manager_id.empty()) {
      LOG(kError) << "Empty Vault Manager ID";
      return false;
    }

    boost::char_separator<char> separator("-");
    boost::tokenizer<boost::char_separator<char>> tokens(vault_manager_id, separator);
    if (std::distance(tokens.begin(), tokens.end()) != 2) {
      LOG(kError) << "Invalid Vault Manager ID";
      return false;
    }

    auto it(tokens.begin());
    if ((*it).length() > 0) {
      process_id_ = (*it);
    } else {
      LOG(kError) << "Invalid Vault Manager ID";
      return false;
    }

    ++it;
    if ((*it).length() > 0) {
      port_ = boost::lexical_cast<uint16_t>(*it);
    } else {
      LOG(kError) << " VaultController: Invalid Vault Manager ID";
      return false;
    }

    if (port_ != 0) {
      thread_ = boost::thread([=] {
          ReceiveKeys();
          ListenForShutdown();
      });
    }
  } catch(std::exception& e)  {
    LOG(kError) << "VaultController: Start: Error receiving keys: " << e.what();
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
                           [&] { return info_received_; })) {  // NOLINT (Philip)
    keys->private_key = keys_.private_key;
    keys->public_key = keys_.public_key;
    keys->identity = keys_.identity;
    keys->validation_token = keys_.validation_token;
    *account_name = account_name_;
    return true;
  }
  return false;
}

void VaultController::ConfirmJoin(bool /*joined*/) {
  LOG(kError) << "ConfirmJoin: Not yet implemented";
}

}  // namespace priv

}  // namespace maidsafe
