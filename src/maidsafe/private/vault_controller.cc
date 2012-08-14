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

#include <chrono>
#include <iterator>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/controller_messages_pb.h"
#include "maidsafe/private/local_tcp_transport.h"
#include "maidsafe/private/utils.h"
#include "maidsafe/private/vault_manager.h"


namespace maidsafe {

namespace priv {

VaultController::VaultController() : process_index_(),
                                     vault_manager_port_(0),
                                     asio_service_(2),
                                     keys_(),
                                     account_name_(),
                                     info_received_(false),
                                     mutex_(),
                                     shutdown_mutex_(),
                                     cond_var_(),
                                     shutdown_cond_var_(),
                                     shutdown_confirmed_(),
                                     stop_callback_() {}

VaultController::~VaultController() {
  asio_service_.Stop();
}

void VaultController::RequestVaultIdentity() {
  protobuf::VaultIdentityRequest vault_identity_request;
  vault_identity_request.set_process_index(process_index_);
  TransportPtr transport(new LocalTcpTransport(asio_service_.service()));
  transport->on_message_received().connect(
      [this, transport](const std::string& message, std::string& /*response*/) {
        HandleVaultIdentityResponse(message, transport);
      });
  transport->on_error().connect([](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
  });

  LOG(kVerbose) << "Sending request for vault identity to port " << vault_manager_port_;
  transport->Send(detail::WrapMessage(MessageType::kVaultIdentityRequest,
                                      vault_identity_request.SerializeAsString()),
                  vault_manager_port_,
                  boost::posix_time::seconds(1));
}

void VaultController::HandleVaultIdentityResponse(const std::string& message,
                                                  TransportPtr /*transport*/) {
  MessageType type;
  std::string payload;
  std::lock_guard<std::mutex> lock(mutex_);
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    info_received_ = false;
    return;
  }

  protobuf::VaultIdentityResponse vault_identity_response;
  if (!vault_identity_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse VaultIdentityResponse.";
    info_received_ = false;
    return;
  }

  if (!asymm::ParseKeys(vault_identity_response.keys(), keys_)) {
    LOG(kError) << "Failed to parse keys.";
    info_received_ = false;
    return;
  }

  account_name_ = vault_identity_response.account_name();
  if (account_name_.empty()) {
    LOG(kError) << "Account name is empty.";
    info_received_ = false;
    return;
  }

  LOG(kVerbose) << "Received VaultIdentityResponse.";
  info_received_ = true;
  cond_var_.notify_all();
}

void VaultController::QueryShutdown() {
  protobuf::VaultShutdownQuery vault_shutdown_query;
  vault_shutdown_query.set_process_index(process_index_);
  TransportPtr transport(new LocalTcpTransport(asio_service_.service()));
  transport->on_message_received().connect(
      [this, transport](const std::string& message, std::string& /*response*/) {
        HandleVaultShutdownResponse(message, transport);
      });
  transport->on_error().connect([](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
  });

  LOG(kVerbose) << "Sending shutdown query to port " << vault_manager_port_;
  transport->Send(detail::WrapMessage(MessageType::kVaultShutdownQuery,
                                      vault_shutdown_query.SerializeAsString()),
                  vault_manager_port_,
                  boost::posix_time::seconds(1));
}

void VaultController::HandleVaultShutdownResponse(const std::string& message,
                                                  TransportPtr /*transport*/) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }

  protobuf::VaultShutdownResponse vault_shutdown_response;
  if (!vault_shutdown_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse VaultShutdownResponse.";
    return;
  }

  if (!vault_shutdown_response.shutdown()) {
    Sleep(boost::posix_time::seconds(1));
    QueryShutdown();
  }

  {
    std::lock_guard<std::mutex> lock(shutdown_mutex_);
    shutdown_confirmed_ = true;
    LOG(kVerbose) << "Shutdown confirmation received";
    shutdown_cond_var_.notify_one();
  }
  stop_callback_();
}


bool VaultController::Start(const std::string& vault_manager_identifier,
                            std::function<void()> stop_callback) {
  if (detail::ParseVmidParameter(vault_manager_identifier, process_index_, vault_manager_port_)) {
    LOG(kError) << "Invalid --vmid parameter " << vault_manager_identifier;
    return false;
  }

  stop_callback_ = stop_callback;
  asio_service_.Start();
  RequestVaultIdentity();
  QueryShutdown();
  return true;
}

bool VaultController::GetIdentity(asymm::Keys* keys, std::string* account_name) {
  if (vault_manager_port_ == 0 || !keys || !account_name)
    return false;
  std::unique_lock<std::mutex> lock(mutex_);
  if (cond_var_.wait_for(lock,
                         std::chrono::seconds(10),
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
