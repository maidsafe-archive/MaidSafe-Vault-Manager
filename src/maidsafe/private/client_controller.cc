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

#include "maidsafe/private/client_controller.h"

#include <chrono>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/controller_messages_pb.h"
#include "maidsafe/private/local_tcp_transport.h"
#include "maidsafe/private/utils.h"
#include "maidsafe/private/vault_manager.h"


namespace maidsafe {

namespace priv {

ClientController::ClientController() : vault_manager_port_(LocalTcpTransport::kMinPort() - 1),
                                       asio_service_(2),
                                       mutex_(),
                                       cond_var_(),
                                       state_(kInitialising) {
  asio_service_.Start();
  PingVaultManager();
}

ClientController::~ClientController() {
  asio_service_.Stop();
}

void ClientController::PingVaultManager() {
  Port vault_manager_port;
  {
    std::lock_guard<std::mutex> lock(mutex_);
    if (state_ != kInitialising) {
      LOG(kWarning) << "Not in initialising state.";
      return;
    }
    vault_manager_port = ++vault_manager_port_;
    if (vault_manager_port > LocalTcpTransport::kMaxPort()) {
      state_ = kFailed;
      LOG(kError) << "Could not connect to any port in range "
                  << LocalTcpTransport::kMinPort() << " to " << LocalTcpTransport::kMaxPort();
      cond_var_.notify_all();
      return;
    }
  }

  protobuf::Ping ping;
  ping.set_ping("");
  TransportPtr transport(new LocalTcpTransport(asio_service_.service()));
  transport->on_message_received().connect(
      [this, transport](const std::string& message, std::string& /*response*/) {
        HandlePingResponse(message, transport);
      });
  transport->on_error().connect([this, transport](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    PingVaultManager();
  });

  LOG(kVerbose) << "Sending ping to port " << vault_manager_port;
  transport->Send(detail::WrapMessage(MessageType::kPing, ping.SerializeAsString()),
                  vault_manager_port,
                  boost::posix_time::seconds(1));
}

void ClientController::HandlePingResponse(const std::string& message, TransportPtr /*transport*/) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return PingVaultManager();
  }

  protobuf::Ping ping;
  if (!ping.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse Ping.";
    return PingVaultManager();
  }

  std::lock_guard<std::mutex> lock(mutex_);
  state_ = kVerified;
  LOG(kSuccess) << "Successfully connected to VaultManager on port " << vault_manager_port_;
  cond_var_.notify_all();
}

void ClientController::StartVaultRequest(const std::string& account_name,
                                         const asymm::Keys& keys,
                                         const boost::asio::ip::udp::endpoint& bootstrap_endpoint,
                                         const std::function<void(bool)>& callback) {  // NOLINT
  protobuf::StartVaultRequest start_vault_request;
  start_vault_request.set_account_name(account_name);
  std::string serialised_keys;
  if (!asymm::SerialiseKeys(keys, serialised_keys)) {
    LOG(kError) << "Failed to serialise keys.";
    return callback(false);
  }
  start_vault_request.set_keys(serialised_keys);
  if (bootstrap_endpoint.address().is_unspecified()) {
    start_vault_request.set_bootstrap_endpoint(
        bootstrap_endpoint.address().to_string() + ":" +
        boost::lexical_cast<std::string>(bootstrap_endpoint.port()));
    LOG(kVerbose) << "Setting bootstrap endpoint to " << start_vault_request.bootstrap_endpoint();
  }

  TransportPtr transport(new LocalTcpTransport(asio_service_.service()));
  transport->on_message_received().connect(
      [this, transport, callback](const std::string& message, std::string& /*response*/) {
        HandleStartVaultResponse(message, transport, callback);
      });
  transport->on_error().connect([this, transport, callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback(false);
  });

  std::lock_guard<std::mutex> lock(mutex_);
  LOG(kVerbose) << "Sending request to start vault to port " << vault_manager_port_;
  transport->Send(detail::WrapMessage(MessageType::kStartVaultRequest,
                                      start_vault_request.SerializeAsString()),
                  vault_manager_port_,
                  boost::posix_time::seconds(10));
}

void ClientController::HandleStartVaultResponse(const std::string& message,
                                                TransportPtr transport,
                                                const std::function<void(bool)>& callback) {  // NOLINT
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    callback(false);
    return;
  }

  protobuf::StartVaultResponse start_vault_response;
  if (!start_vault_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse StartVaultResponse.";
    callback(false);
    return;
  }

  callback(start_vault_response.result());
}

bool ClientController::StartVault(const asymm::Keys& keys,
                                  const std::string& account_name,
                                  const boost::asio::ip::udp::endpoint& bootstrap_endpoint) {
  {
    std::unique_lock<std::mutex> lock(mutex_);
    if (!cond_var_.wait_for(lock,
                            std::chrono::seconds(3),
                            [&] { return state_ != kInitialising; })) {
      LOG(kError) << "Timed out waiting for ClientController initialisation.";
      return false;
    }
    if (state_ != kVerified) {
      LOG(kError) << "ClientController is uninitialised.";
      return false;
    }
  }

  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false), local_result(false);

  StartVaultRequest(account_name, keys, bootstrap_endpoint,
                    [&](bool result) {
                      std::lock_guard<std::mutex> lock(local_mutex);
                      local_result = result;
                      done = true;
                      local_cond_var.notify_one();
                    });

  std::unique_lock<std::mutex> lock(local_mutex);
  if (!local_cond_var.wait_for(lock,
                               std::chrono::seconds(10),
                               [&] { return done; })) {
    LOG(kError) << "Timed out waiting for reply.";
    return false;
  }
  if (!local_result)
    LOG(kError) << "Failed starting vault.";
  return local_result;
}

bool ClientController::StopVault(const asymm::PlainText& /*data*/,
                                 const asymm::Signature& /*signature*/,
                                 const asymm::Identity& /*identity*/) {
                                                                LOG(kError) << "StopVault: Not implemented.";
  return false;
}

}  // namespace priv

}  // namespace maidsafe
