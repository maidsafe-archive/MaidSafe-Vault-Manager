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

#include "maidsafe/lifestuff_manager/vault_controller.h"

#include <chrono>
#include <iterator>

#include "boost/algorithm/string.hpp"
#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/types.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/lifestuff_manager/controller_messages_pb.h"
#include "maidsafe/lifestuff_manager/local_tcp_transport.h"
#include "maidsafe/lifestuff_manager/return_codes.h"
#include "maidsafe/lifestuff_manager/utils.h"
#include "maidsafe/lifestuff_manager/lifestuff_manager.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff_manager {

namespace {

boost::asio::ip::udp::endpoint GetEndpoint(const std::string& ip, int port) {
  boost::asio::ip::udp::endpoint ep;
  ep.port(port);
  ep.address(boost::asio::ip::address::from_string(ip));
  return ep;
}

}  // namespace

typedef std::function<void()> VoidFunction;
typedef std::function<void(bool)> VoidFunctionBoolParam;  // NOLINT (Philip)

namespace bai = boost::asio::ip;

VaultController::VaultController(const std::string& lifestuff_manager_identifier,
                                 VoidFunction stop_callback)
    : process_index_(-1),
      lifestuff_manager_port_(0),
      local_port_(0),
      pmid_(),
      bootstrap_endpoints_(),
      stop_callback_(stop_callback),
      asio_service_(3),
      receiving_transport_(std::make_shared<LocalTcpTransport>(asio_service_.service())) {
  if (!stop_callback_)
    ThrowError(CommonErrors::invalid_parameter);
  if (lifestuff_manager_identifier != "test") {
    detail::ParseVmidParameter(lifestuff_manager_identifier,
                               process_index_,
                               lifestuff_manager_port_);
    asio_service_.Start();
    OnMessageReceived::slot_type on_message_slot(
        [this] (const std::string& message, Port lifestuff_manager_port) {
          HandleReceivedRequest(message, lifestuff_manager_port);
        });
    detail::StartControllerListeningPort(receiving_transport_, on_message_slot, local_port_);
    RequestVaultIdentity(local_port_);
  }
}

VaultController::~VaultController() {
  receiving_transport_->StopListening();
}

bool VaultController::GetIdentity(
    std::unique_ptr<passport::Pmid>& pmid,
    std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints) {
  if (lifestuff_manager_port_ == 0) {
    std::cout << "Invalid LifeStuffManager port." << std::endl;
    LOG(kError) << "Invalid LifeStuffManager port.";
    return false;
  }
  pmid.reset(new passport::Pmid(*pmid_));
  bootstrap_endpoints = bootstrap_endpoints_;
  return true;
}

void VaultController::ConfirmJoin() {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false);
  protobuf::VaultJoinedNetwork vault_joined_network;
  vault_joined_network.set_process_index(process_index_);
  vault_joined_network.set_joined(true);

  VoidFunction callback = [&] {
    std::lock_guard<std::mutex> lock(local_mutex);
    done = true;
    local_cond_var.notify_one();
  };

  TransportPtr request_transport(std::make_shared<LocalTcpTransport>(asio_service_.service()));
  int result(0);
  request_transport->Connect(lifestuff_manager_port_, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to LifeStuffManager.";
    return;
  }
  request_transport->on_message_received().connect(
      [this, callback] (const std::string& message, Port /*lifestuff_manager_port*/) {
        HandleVaultJoinedAck(message, callback);
      });
  request_transport->on_error().connect([callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback();
  });

  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Sending joined notification to port " << lifestuff_manager_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kVaultJoinedNetwork,
                                              vault_joined_network.SerializeAsString()),
                          lifestuff_manager_port_);

  if (!local_cond_var.wait_for(lock, std::chrono::seconds(3), [&] { return done; }))  // NOLINT (Fraser)
    LOG(kError) << "Timed out waiting for reply.";
}

void VaultController::HandleVaultJoinedAck(const std::string& message, VoidFunction callback) {
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
    std::vector<boost::asio::ip::udp::endpoint> &bootstrap_endpoints) {
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
  request_transport->Connect(lifestuff_manager_port_, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to LifeStuffManager.";
    return false;
  }
  request_transport->on_message_received().connect(
      [this, callback, &bootstrap_endpoints] (const std::string& message,
                                             Port /*lifestuff_manager_port*/) {
        HandleBootstrapResponse(message, bootstrap_endpoints, callback);
      });
  request_transport->on_error().connect([callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback(false);
  });
  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Requesting bootstrap nodes from port " << lifestuff_manager_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kBootstrapRequest,
                                              request.SerializeAsString()),
                          lifestuff_manager_port_);
  if (!local_cond_var.wait_for(lock, std::chrono::seconds(3), [&] { return done; })) {  // NOLINT (Philip)
    LOG(kError) << "Timed out waiting for reply.";
    return false;
  }
  return success;
}

void VaultController::HandleBootstrapResponse(
    const std::string& message,
    std::vector<boost::asio::ip::udp::endpoint> &bootstrap_endpoints,
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

  if (bootstrap_response.bootstrap_endpoint_ip_size() !=
      bootstrap_response.bootstrap_endpoint_port_size()) {
    LOG(kWarning) << "Number of ports in endpoints does not equal number of addresses";
  }
  int size(std::min(bootstrap_response.bootstrap_endpoint_ip_size(),
                    bootstrap_response.bootstrap_endpoint_port_size()));
  for (int i(0); i < size; ++i) {
    try {
      bootstrap_endpoints.push_back(GetEndpoint(bootstrap_response.bootstrap_endpoint_ip(i),
                                                bootstrap_response.bootstrap_endpoint_port(i)));
    }
    catch(...) { continue; }
  }
  bootstrap_endpoints_ = bootstrap_endpoints;
  callback(true);
}

bool VaultController::SendEndpointToLifeStuffManager(
    const boost::asio::ip::udp::endpoint& endpoint) {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false), success(false);
  protobuf::SendEndpointToLifeStuffManagerRequest request;
  request.set_bootstrap_endpoint_ip(endpoint.address().to_string());
  request.set_bootstrap_endpoint_port(endpoint.port());

  VoidFunctionBoolParam callback = [&] (bool result) {
    std::lock_guard<std::mutex> lock(local_mutex);
    done = true;
    success = result;
    local_cond_var.notify_one();
  };

  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  int result(0);
  request_transport->Connect(lifestuff_manager_port_, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to LifeStuffManager.";
    return false;
  }
    request_transport->on_message_received().connect(
      [this, callback] (const std::string& message, Port /*lifestuff_manager_port*/) {
        HandleSendEndpointToLifeStuffManagerResponse(message, callback);
      });
    request_transport->on_error().connect([callback](const int& error) {
      LOG(kError) << "Transport reported error code " << error;
      callback(false);
  });

  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Sending bootstrap endpoint to port " << lifestuff_manager_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kSendEndpointToLifeStuffManagerRequest,
                                              request.SerializeAsString()),
                          lifestuff_manager_port_);
  if (!local_cond_var.wait_for(lock, std::chrono::seconds(3), [&] { return done; })) {  // NOLINT (Philip)
    LOG(kError) << "Timed out waiting for reply.";
    return false;
  }
  return success;
}

void VaultController::HandleSendEndpointToLifeStuffManagerResponse(const std::string& message,
                                                                   VoidFunctionBoolParam callback) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    callback(false);
    return;
  }

  protobuf::SendEndpointToLifeStuffManagerResponse send_endpoint_response;
  if (!send_endpoint_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse SendEndpointToLifeStuffManagerResponse.";
    callback(false);
    return;
  }
  callback(send_endpoint_response.result());
}

void VaultController::RequestVaultIdentity(uint16_t listening_port) {
  std::mutex local_mutex;
  std::condition_variable local_cond_var;

  protobuf::VaultIdentityRequest vault_identity_request;
  vault_identity_request.set_process_index(process_index_);
  vault_identity_request.set_listening_port(listening_port);
  vault_identity_request.set_version(VersionToInt(kApplicationVersion));

  TransportPtr request_transport(std::make_shared<LocalTcpTransport>(asio_service_.service()));
  int connect_result(0);
  request_transport->Connect(lifestuff_manager_port_, connect_result);
  if (connect_result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to LifeStuffManager.";
    ThrowError(CommonErrors::uninitialised);
  }

  auto connection(request_transport->on_message_received().connect(
      [this, &local_mutex, &local_cond_var] (const std::string& message,
                                             Port /*lifestuff_manager_port*/) {
        HandleVaultIdentityResponse(message, local_mutex);
        local_cond_var.notify_one();
      }));
  auto error_connection(request_transport->on_error().connect([] (const int& error) {
    LOG(kError) << "Transport reported error code " << error;
  }));

  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Sending request for vault identity to port " << lifestuff_manager_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kVaultIdentityRequest,
                                              vault_identity_request.SerializeAsString()),
                          lifestuff_manager_port_);

  if (!local_cond_var.wait_for(lock,
                               std::chrono::seconds(3),
                               [this] () { return static_cast<bool>(pmid_); })) {
    connection.disconnect();
    error_connection.disconnect();
    LOG(kError) << "Timed out waiting for reply.";
    ThrowError(CommonErrors::uninitialised);
  }
}

void VaultController::HandleVaultIdentityResponse(const std::string& message, std::mutex& mutex) {
  MessageType type;
  std::string payload;
  std::lock_guard<std::mutex> lock(mutex);
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }

  protobuf::VaultIdentityResponse vault_identity_response;
  if (!vault_identity_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse VaultIdentityResponse.";
    return;
  }

  pmid_.reset(
      new passport::Pmid(passport::ParsePmid(NonEmptyString(vault_identity_response.pmid()))));

  if (vault_identity_response.bootstrap_endpoint_ip_size() !=
      vault_identity_response.bootstrap_endpoint_port_size()) {
    LOG(kWarning) << "Number of ports in endpoints does not equal number of addresses";
  }
  int size(std::min(vault_identity_response.bootstrap_endpoint_ip_size(),
                    vault_identity_response.bootstrap_endpoint_port_size()));
  for (int i(0); i < size; ++i) {
    try {
      bootstrap_endpoints_.push_back(
            GetEndpoint(vault_identity_response.bootstrap_endpoint_ip(i),
                        vault_identity_response.bootstrap_endpoint_port(i)));
    }
    catch(...) { continue; }
  }

  LOG(kInfo) << "Received VaultIdentityResponse.";
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

}  // namespace lifestuff_manager

}  // namespace maidsafe
