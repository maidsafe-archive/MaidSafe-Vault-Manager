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

#include "boost/algorithm/string.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/process_management/controller_messages_pb.h"
#include "maidsafe/private/process_management/local_tcp_transport.h"
#include "maidsafe/private/process_management/utils.h"
#include "maidsafe/private/process_management/invigilator.h"


namespace maidsafe {

namespace priv {

namespace process_management {

typedef std::function<void()> VoidFunction;
typedef std::function<void(bool)> VoidFunctionBoolParam;  // NOLINT (Philip)

namespace bai = boost::asio::ip;

VaultController::VaultController()
    : process_index_(),
      invigilator_port_(0),
      local_port_(0),
      asio_service_(3),
      receiving_transport_(new LocalTcpTransport(asio_service_.service())),
      fob_(),
      account_name_(),
      bootstrap_endpoints_(),
      stop_callback_(),
      setuid_succeeded_() {
#ifndef MAIDSAFE_WIN32
  int result(system("id -u maidsafe > ./uid.txt"));
  if (result) {
    setuid_succeeded_ = false;
    LOG(kError) << "Failed to determine uid of lifestuff user";
    boost::system::error_code error;
    fs::remove(fs::path(".") / "uid.txt", error);
    if (error)
      LOG(kError) << "Failed to remove uid file.";
  } else {
    std::string content;
    ReadFile(fs::path(".") / "uid.txt", &content);
    boost::trim(content);
    try {
      uid_t uid(boost::lexical_cast<uid_t>(content));
      boost::system::error_code error;
      fs::remove(fs::path(".") / "uid.txt", error);
      if (error)
        LOG(kError) << "Failed to remove uid file.";
      LOG(kInfo) << "UID of lifestuff user: " << uid;
      if (uid == 0) {
        LOG(kError) << "UID is 0, but vault may not run as root.";
        setuid_succeeded_ = false;
      } else if (setuid(uid) == -1) {
        LOG(kError) << "failed to set uid";
        setuid_succeeded_ = false;
      } else {
        LOG(kInfo) << "Successfully set UID to: " << getuid();
        setuid_succeeded_ = true;
      }
      LOG(kVerbose) << "Vault is now running as UID: " << getuid();
    } catch(...) {
      setuid_succeeded_ = false;
      LOG(kError) << "Failed to retrieve uid of lifestuff user.";
    }
  }
#else
  setuid_succeeded_ = true;
#endif
}

VaultController::~VaultController() {
  receiving_transport_->StopListening();
  receiving_transport_.reset();
  asio_service_.Stop();
}

bool VaultController::StartListeningPort() {
  local_port_ = detail::GetRandomPort();
  int count(0), result(1);
  receiving_transport_->StartListening(local_port_, result);
  while (result != kSuccess && count++ < 100) {
    local_port_ = detail::GetRandomPort();
    receiving_transport_->StartListening(local_port_, result);
  }

  if (result != kSuccess) {
    LOG(kError) << "Failed to start listening port. Aborting initialisation.";
    return false;
  }

  receiving_transport_->on_message_received().connect(
      [this] (const std::string& message, Port invigilator_port) {
        HandleReceivedRequest(message, invigilator_port);
      });
  receiving_transport_->on_error().connect(
      [] (const int& error) {
        LOG(kError) << "Transport reported error code " << error;
      });

  return true;
}

bool VaultController::Start(const std::string& invigilator_identifier,
                            VoidFunction stop_callback) {
#ifndef USE_TEST_KEYS
  if (!setuid_succeeded_) {
    LOG(kError) << "In constructor, failed to set the user ID to the correct user";
    return false;
  }
#endif
  if (!detail::ParseVmidParameter(invigilator_identifier,
                                  process_index_,
                                  invigilator_port_)) {
    LOG(kError) << "Invalid --vmid parameter " << invigilator_identifier;
    return false;
  }

  stop_callback_ = stop_callback;
  asio_service_.Start();
  if (!StartListeningPort()) {
    LOG(kError) << "Failed to start listening port.";
    return false;
  }
  return RequestVaultIdentity(local_port_);
}

bool VaultController::GetIdentity(
    Fob& fob,
    std::string& account_name,
    std::vector<std::pair<std::string, uint16_t>> &bootstrap_endpoints) {
  if (invigilator_port_ == 0) {
    LOG(kError) << "Invalid Invigilator port.";
    return false;
  }
  fob = fob_;
  account_name = account_name_;
  bootstrap_endpoints = bootstrap_endpoints_;
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

bool VaultController::GetBootstrapNodes(
    std::vector<std::pair<std::string, uint16_t>> &bootstrap_endpoints) {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false), success(false);
  protobuf::BootstrapRequest request;
  uint32_t message_id(maidsafe::RandomUint32());
  request.set_message_id(message_id);

  VoidFunctionBoolParam callback = [&] (bool result) {
    std::lock_guard<std::mutex> lock(local_mutex);
    done = true;
    success = result;
    local_cond_var.notify_one();
  };

  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  int result(0);
  request_transport->Connect(invigilator_port_, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to Invigilator.";
    return false;
  }
  request_transport->on_message_received().connect(
      [this, callback, &bootstrap_endpoints] (const std::string& message,
                                             Port /*invigilator_port*/) {
        HandleBootstrapResponse(message, bootstrap_endpoints, callback);
      });
  request_transport->on_error().connect([callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback(false);
  });
  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Requesting bootstrap nodes from port " << invigilator_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kBootstrapRequest,
                                              request.SerializeAsString()),
                          invigilator_port_);
  if (!local_cond_var.wait_for(lock, std::chrono::seconds(3), [&] { return done; })) {  // NOLINT (Philip)
    LOG(kError) << "Timed out waiting for reply.";
    return false;
  }
  return success;
}

void VaultController::HandleBootstrapResponse(const std::string& message,
                             std::vector<std::pair<std::string, uint16_t>> &bootstrap_endpoints,
                             VoidFunctionBoolParam callback) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    callback(false);
    return;
  }

  protobuf::BootstrapResponse bootstrap_response;
  if (!bootstrap_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse BootstrapResponse.";
    callback(false);
    return;
  }

  std::string address;
  uint16_t port(0);
  if (bootstrap_response.bootstrap_endpoint_ip_size()
        != bootstrap_response.bootstrap_endpoint_port_size()) {
    LOG(kWarning) << "Number of ports in endpoints does not equal number of addresses";
  }
  int size(std::min(bootstrap_response.bootstrap_endpoint_ip_size(),
                    bootstrap_response.bootstrap_endpoint_port_size()));
  for (int i(0); i < size; ++i) {
    address = bootstrap_response.bootstrap_endpoint_ip(i);
    port = static_cast<uint16_t>(bootstrap_response.bootstrap_endpoint_port(i));
    bootstrap_endpoints.push_back(std::pair<std::string, uint16_t>(address, port));
  }
  bootstrap_endpoints_ = bootstrap_endpoints;
  callback(true);
}

bool VaultController::SendEndpointToInvigilator(
    const std::pair<std::string, uint16_t>& endpoint) {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false), success(false);
  protobuf::SendEndpointToInvigilatorRequest request;
  request.set_bootstrap_endpoint_ip(endpoint.first);
  request.set_bootstrap_endpoint_port(endpoint.second);

  VoidFunctionBoolParam callback = [&] (bool result) {
    std::lock_guard<std::mutex> lock(local_mutex);
    done = true;
    success = result;
    local_cond_var.notify_one();
  };

  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  int result(0);
  request_transport->Connect(invigilator_port_, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to Invigilator.";
    return false;
  }
    request_transport->on_message_received().connect(
      [this, callback] (const std::string& message, Port /*invigilator_port*/) {
        HandleSendEndpointToInvigilatorResponse(message, callback);
      });
    request_transport->on_error().connect([callback](const int& error) {
      LOG(kError) << "Transport reported error code " << error;
      callback(false);
  });

  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Sending bootstrap endpoint to port " << invigilator_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kSendEndpointToInvigilatorRequest,
                                              request.SerializeAsString()),
                          invigilator_port_);
  if (!local_cond_var.wait_for(lock, std::chrono::seconds(3), [&] { return done; })) {  // NOLINT (Philip)
    LOG(kError) << "Timed out waiting for reply.";
    return false;
  }
  return success;
}

void VaultController::HandleSendEndpointToInvigilatorResponse(const std::string& message,
                                                              VoidFunctionBoolParam callback) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    callback(false);
    return;
  }

  protobuf::SendEndpointToInvigilatorResponse send_endpoint_response;
  if (!send_endpoint_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse SendEndpointToInvigilatorResponse.";
    callback(false);
    return;
  }
  callback(send_endpoint_response.result());
}

bool VaultController::RequestVaultIdentity(uint16_t listening_port) {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;

  protobuf::VaultIdentityRequest vault_identity_request;
  vault_identity_request.set_process_index(process_index_);
  vault_identity_request.set_listening_port(listening_port);
  vault_identity_request.set_version(VersionToInt(kApplicationVersion));

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
        result = HandleVaultIdentityResponse(message, local_mutex);
        if (result)
          local_cond_var.notify_one();
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
                                                  std::mutex& mutex) {
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

  fob_ = utils::ParseFob(NonEmptyString(vault_identity_response.fob()));

  account_name_ = vault_identity_response.account_name();
  if (account_name_.empty()) {
    LOG(kError) << "Account name is empty.";
    return false;
  }
  std::string address;
  uint16_t port(0);
  if (vault_identity_response.bootstrap_endpoint_ip_size()
        != vault_identity_response.bootstrap_endpoint_port_size()) {
    LOG(kWarning) << "Number of ports in endpoints does not equal number of addresses";
  }
  int size(std::min(vault_identity_response.bootstrap_endpoint_ip_size(),
                    vault_identity_response.bootstrap_endpoint_port_size()));
  for (int i(0); i < size; ++i) {
    address = vault_identity_response.bootstrap_endpoint_ip(i);
    port = static_cast<uint16_t>(vault_identity_response.bootstrap_endpoint_port(i));
    bootstrap_endpoints_.push_back(std::pair<std::string, uint16_t>(address, port));
  }

  LOG(kInfo) << "Received VaultIdentityResponse.";
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
