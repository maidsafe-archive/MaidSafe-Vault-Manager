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

VaultController::VaultController()
    : process_index_(),
      invigilator_port_(0),
      asio_service_(3),
      receiving_transport_(new LocalTcpTransport(asio_service_.service())),
      keys_(),
      account_name_(),
      bootstrap_nodes_(),
      shutdown_requested_(false),
      stop_callback_() {}

VaultController::~VaultController() {
  receiving_transport_.reset();
  asio_service_.Stop();
}

bool VaultController::Start(const std::string& invigilator_identifier,
                            std::function<void()> stop_callback) {
  if (!detail::ParseVmidParameter(invigilator_identifier,
                                  process_index_,
                                  invigilator_port_)) {
    LOG(kError) << "Invalid --vmid parameter " << invigilator_identifier;
    return false;
  }

  stop_callback_ = stop_callback;
  asio_service_.Start();
  uint16_t listening_port(detail::GetRandomPort());
  RequestVaultIdentity(listening_port);
  receiving_transport_->on_message_received().connect(
      [this](const std::string& message, Port invigilator_port) {
        HandleReceivedRequest(message, invigilator_port);
      });
  receiving_transport_->on_error().connect([](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
  });

  receiving_transport_->StartListening(listening_port);

  return true;
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

  std::function<void()> callback = [&] {
    std::lock_guard<std::mutex> lock(local_mutex);
    done = true;
    local_cond_var.notify_one();
  };

  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  if (request_transport->Connect(invigilator_port_) != kSuccess) {
    LOG(kError) << "Failed to connect request transport to Invigilator.";
      return;
  }
  request_transport->on_message_received().connect(
      [this, callback](const std::string& message, Port /*invigilator_port*/) {
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
                                           std::function<void()> callback) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }

  protobuf::VaultJoinedNetworkAck vault_joined_network_ack;
  if (!vault_joined_network_ack.ParseFromString(payload) ||
      !vault_joined_network_ack.IsInitialized()) {
    LOG(kError) << "Failed to parse VaultJoinedNetworkAck.";
    return;
  }
  callback();
}

void VaultController::RequestVaultIdentity(uint16_t listening_port) {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;

  protobuf::VaultIdentityRequest vault_identity_request;
  vault_identity_request.set_process_index(process_index_);
  vault_identity_request.set_listening_port(listening_port);

  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  if (request_transport->Connect(invigilator_port_) != kSuccess) {
    LOG(kError) << "Failed to connect request transport to Invigilator.";
      return;
  }
  request_transport->on_message_received().connect(
      [this, &local_mutex, &local_cond_var](const std::string& message,
                                            Port /*invigilator_port*/) {
        HandleVaultIdentityResponse(message, local_mutex, local_cond_var);
      });
  request_transport->on_error().connect([](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
  });

  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Sending request for vault identity to port " << invigilator_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kVaultIdentityRequest,
                                              vault_identity_request.SerializeAsString()),
                          invigilator_port_);

  if (!local_cond_var.wait_for(lock,
                               std::chrono::seconds(3),
                               [&] { return !account_name_.empty(); })) {  // NOLINT (Fraser)
    LOG(kError) << "Timed out waiting for reply.";
    return;
  }
}

void VaultController::HandleVaultIdentityResponse(const std::string& message,
                                                  std::mutex& mutex,
                                                  std::condition_variable& cond_var) {
  MessageType type;
  std::string payload;
  std::lock_guard<std::mutex> lock(mutex);
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }

  protobuf::VaultIdentityResponse vault_identity_response;
  if (!vault_identity_response.ParseFromString(payload) ||
      !vault_identity_response.IsInitialized()) {
    LOG(kError) << "Failed to parse VaultIdentityResponse.";
    return;
  }

  if (!asymm::ParseKeys(vault_identity_response.keys(), keys_)) {
    LOG(kError) << "Failed to parse keys.";
    return;
  }

  account_name_ = vault_identity_response.account_name();
  if (account_name_.empty()) {
    LOG(kError) << "Account name is empty.";
    return;
  }

  LOG(kVerbose) << "Received VaultIdentityResponse.";
  cond_var.notify_one();
}

void VaultController::HandleReceivedRequest(const std::string& message, Port peer_port) {
  /*assert(peer_port == invigilator_port_);*/  // Invigilator does not currently use
                                               // its established port to contact VaultController
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
    case MessageType::kVaultShutdownResponseAck:
      HandleVaultShutdownResponseAck(payload, response);
      break;
    default:
      return;
  }
  if (type != MessageType::kVaultShutdownResponseAck)
    receiving_transport_->Send(response, peer_port);
}

void VaultController::HandleVaultShutdownRequest(const std::string& request,
                                                 std::string& response) {
  LOG(kError) << "Received shutdown request.";
  protobuf::VaultShutdownRequest vault_shutdown_request;
  protobuf::VaultShutdownResponse vault_shutdown_response;
  if (!vault_shutdown_request.ParseFromString(request) ||
      !vault_shutdown_request.IsInitialized()) {
    LOG(kError) << "Failed to parse VaultShutdownRequest.";
    vault_shutdown_response.set_shutdown(false);
  } else if (vault_shutdown_request.process_index() != process_index_) {
    LOG(kError) << "This shutdown request is not for this process.";
    vault_shutdown_response.set_shutdown(false);
  } else {
    vault_shutdown_response.set_shutdown(true);
  }
  vault_shutdown_response.set_process_index(process_index_);
  response = detail::WrapMessage(MessageType::kVaultShutdownResponse,
                                 vault_shutdown_response.SerializeAsString());
  shutdown_requested_ = true;
}

void VaultController::HandleVaultShutdownResponseAck(const std::string& request,
                                                     std::string& response) {
  protobuf::VaultShutdownResponseAck vault_shutdown_response_ack;
  if (!vault_shutdown_response_ack.ParseFromString(request) ||
      !vault_shutdown_response_ack.IsInitialized()) {
    LOG(kError) << "Failed to parse VaultShutdownResponseAck.";
  } else if (!vault_shutdown_response_ack.ack()) {
    LOG(kError) << "VaultShutdownResponseAck is false.";
  } else if (!shutdown_requested_) {
    LOG(kError) << "VaultShutdownResponseAck is unexpected.";
  } else {
    stop_callback_();
  }
  response.clear();
}

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
