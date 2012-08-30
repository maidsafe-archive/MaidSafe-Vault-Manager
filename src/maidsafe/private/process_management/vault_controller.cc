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

#include "maidsafe/private/process_management/vault_controller.h"

#include <chrono>
#include <iterator>

#include "maidsafe/common/log.h"
#include "maidsafe/common/return_codes.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/process_management/controller_messages_pb.h"
#include "maidsafe/private/process_management/local_tcp_transport.h"
#include "maidsafe/private/process_management/utils.h"
#include "maidsafe/private/process_management/invigilator.h"


namespace maidsafe {

namespace priv {

namespace process_management {

typedef std::function<void()> VoidFunction;

VaultController::VaultController()
    : process_index_(),
      invigilator_port_(0),
      asio_service_(3),
      receiving_transport_(new LocalTcpTransport(asio_service_.service())),
      keys_(),
      account_name_(),
      bootstrap_nodes_(),
      stop_callback_() {}

VaultController::~VaultController() {
  receiving_transport_.reset();
  asio_service_.Stop();
}

bool VaultController::Start(const std::string& invigilator_identifier,
                            VoidFunction stop_callback) {
  if (!detail::ParseVmidParameter(invigilator_identifier,
                                  process_index_,
                                  invigilator_port_)) {
    LOG(kError) << "Invalid --vmid parameter " << invigilator_identifier;
    return false;
  }

  stop_callback_ = stop_callback;
  asio_service_.Start();
  uint16_t listening_port(detail::GetRandomPort());
  int result(0);
  receiving_transport_->StartListening(listening_port, result);
  while (result != kSuccess) {
    ++listening_port;
    receiving_transport_->StartListening(listening_port, result);
  }

  receiving_transport_->on_message_received().connect(
      [this] (const std::string& message, Port invigilator_port) {
        HandleReceivedRequest(message, invigilator_port);
      });
  receiving_transport_->on_error().connect([] (const int& error) {
    LOG(kError) << "Transport reported error code: " << error;
  });


  return RequestVaultIdentity(listening_port);
}

bool VaultController::GetIdentity(asymm::Keys* keys, std::string* account_name) {
  if (invigilator_port_ == 0 || !keys || !account_name)
    return false;
  keys->private_key = keys_.private_key;
  keys->public_key = keys_.public_key;
  keys->identity = keys_.identity;
  keys->validation_token = keys_.validation_token;
  *account_name = account_name_;
  return true;
}

void VaultController::ConfirmJoin(bool joined) {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false);
  protobuf::VaultJoinedNetwork vault_joined_network;
  vault_joined_network.set_process_index(process_index_);
  vault_joined_network.set_joined(joined);

  VoidFunction callback = [&] {
    std::lock_guard<std::mutex> lock(local_mutex);
    done = true;
    local_cond_var.notify_one();
  };

  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  int result(0);
  request_transport->Connect(invigilator_port_, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to Invigilator.";
    return;
  }
  request_transport->on_message_received().connect(
      [this, callback] (const std::string& message, Port /*invigilator_port*/) {
        HandleVaultJoinedAck(message, callback);
      });
  request_transport->on_error().connect([callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback();
  });

  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Sending joined notification to port " << invigilator_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kVaultJoinedNetwork,
                                              vault_joined_network.SerializeAsString()),
                          invigilator_port_);

  if (!local_cond_var.wait_for(lock, std::chrono::seconds(3), [&] { return done; }))  // NOLINT (Fraser)
    LOG(kError) << "Timed out waiting for reply.";
}

void VaultController::HandleVaultJoinedAck(const std::string& message,
                                           VoidFunction callback) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }

  protobuf::VaultJoinedNetworkAck vault_joined_network_ack;
  if (!vault_joined_network_ack.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse VaultJoinedNetworkAck.";
    return;
  }
  callback();
}

bool VaultController::RequestVaultIdentity(uint16_t listening_port) {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;

  protobuf::VaultIdentityRequest vault_identity_request;
  vault_identity_request.set_process_index(process_index_);
  vault_identity_request.set_listening_port(listening_port);

  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  int connect_result(0);
  request_transport->Connect(invigilator_port_, connect_result);
  if (connect_result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to Invigilator.";
    return false;
  }

  bool result(false);
  auto connection(request_transport->on_message_received().connect(
      [this, &local_mutex, &local_cond_var, &result] (const std::string& message,
                                                      Port /*invigilator_port*/) {
        result = HandleVaultIdentityResponse(message, local_mutex, local_cond_var);
      }));
  auto error_connection(request_transport->on_error().connect([] (const int& error) {
    LOG(kError) << "Transport reported error code " << error;
  }));

  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Sending request for vault identity to port " << invigilator_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kVaultIdentityRequest,
                                              vault_identity_request.SerializeAsString()),
                          invigilator_port_);

  if (!local_cond_var.wait_for(lock,
                               std::chrono::seconds(3),
                               [&] { return !account_name_.empty(); })) {  // NOLINT (Fraser)
    connection.disconnect();
    error_connection.disconnect();
    LOG(kError) << "Timed out waiting for reply.";
    return false;
  }

  return result;
}

bool VaultController::HandleVaultIdentityResponse(const std::string& message,
                                                  std::mutex& mutex,
                                                  std::condition_variable& cond_var) {
  MessageType type;
  std::string payload;
  std::lock_guard<std::mutex> lock(mutex);
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return false;
  }

  protobuf::VaultIdentityResponse vault_identity_response;
  if (!vault_identity_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse VaultIdentityResponse.";
    return false;
  }

  if (!asymm::ParseKeys(vault_identity_response.keys(), keys_)) {
    LOG(kError) << "Failed to parse keys.";
    return false;
  }

  account_name_ = vault_identity_response.account_name();
  if (account_name_.empty()) {
    LOG(kError) << "Account name is empty.";
    return false;
  }

  LOG(kVerbose) << "Received VaultIdentityResponse.";
  cond_var.notify_one();
  return true;
}

void VaultController::HandleReceivedRequest(const std::string& message, Port /*peer_port*/) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }
  LOG(kVerbose) << "HandleReceivedRequest: message type " << static_cast<int>(type) << " received.";
  std::string response;
  switch (type) {
    case MessageType::kVaultShutdownRequest:
      HandleVaultShutdownRequest(payload, response);
      break;
    default:
      return;
  }
}

void VaultController::HandleVaultShutdownRequest(const std::string& request,
                                                 std::string& /*response*/) {
  LOG(kInfo) << "Received shutdown request.";
  protobuf::VaultShutdownRequest vault_shutdown_request;
  protobuf::VaultShutdownResponse vault_shutdown_response;
  if (!vault_shutdown_request.ParseFromString(request)) {
    LOG(kError) << "Failed to parse VaultShutdownRequest.";
    vault_shutdown_response.set_shutdown(false);
  } else if (vault_shutdown_request.process_index() != process_index_) {
    LOG(kError) << "This shutdown request is not for this process.";
    vault_shutdown_response.set_shutdown(false);
  } else {
    vault_shutdown_response.set_shutdown(true);
  }
  vault_shutdown_response.set_process_index(process_index_);
  stop_callback_();
}

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
