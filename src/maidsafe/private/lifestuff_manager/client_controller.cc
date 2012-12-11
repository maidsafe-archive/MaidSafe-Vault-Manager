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

#include "maidsafe/private/lifestuff_manager/client_controller.h"

#include <chrono>
#include <limits>

#include "maidsafe/common/config.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/data_types/fob.h"
#include "maidsafe/private/lifestuff_manager/controller_messages_pb.h"
#include "maidsafe/private/lifestuff_manager/lifestuff_manager.h"
#include "maidsafe/private/lifestuff_manager/local_tcp_transport.h"
#include "maidsafe/private/lifestuff_manager/return_codes.h"
#include "maidsafe/private/lifestuff_manager/utils.h"


namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

typedef std::function<void(bool)> VoidFunctionBoolParam;  // NOLINT (Philip)

ClientController::ClientController(
    std::function<void(const NonEmptyString&)> on_new_version_available_slot)
#ifdef TESTING
        : lifestuff_manager_port_(detail::GetTestLifeStuffManagerPort() == 0 ?
                                  LifeStuffManager::kDefaultPort() + 100 :
                                  detail::GetTestLifeStuffManagerPort()),
#else
        : lifestuff_manager_port_(LifeStuffManager::kDefaultPort()),
#endif
          local_port_(0),
          on_new_version_available_(),
          state_(kInitialising),
          bootstrap_nodes_(),
          joining_vaults_(),
          joining_vaults_mutex_(),
          joining_vaults_conditional_(),
          asio_service_(3),
          receiving_transport_(std::make_shared<LocalTcpTransport>(asio_service_.service())) {
  asio_service_.Start();
  OnMessageReceived::slot_type on_message_slot(
      [this](const std::string& message, Port lifestuff_manager_port) {
          HandleReceivedRequest(message, lifestuff_manager_port);
      });
  if (!detail::StartControllerListeningPort(receiving_transport_, on_message_slot, local_port_)) {
    LOG(kError) << "Failed to start listening port. Won't be able to start vaults.";
    state_ = kFailed;
  }

  std::string path_to_new_installer;
  if (!ConnectToLifeStuffManager(path_to_new_installer)) {
    LOG(kError) << "Failed to connect to lifestuff_manager. Object useless.";
    state_ = kFailed;
  } else {
    state_ = kVerified;
  }
  on_new_version_available_.connect(on_new_version_available_slot);
  if (!path_to_new_installer.empty())
    on_new_version_available_(NonEmptyString(path_to_new_installer));
}

ClientController::~ClientController() {
  receiving_transport_->StopListening();
}

#ifdef TESTING
void ClientController::SetTestEnvironmentVariables(uint16_t test_lifestuff_manager_port,
                                                   fs::path test_env_root_dir,
                                                   fs::path path_to_vault,
                                                   std::vector<std::string> bootstrap_ips) {
  detail::SetTestEnvironmentVariables(test_lifestuff_manager_port,
                                      test_env_root_dir,
                                      path_to_vault,
                                      bootstrap_ips);
}
#endif

bool ClientController::BootstrapEndpoints(std::vector<EndPoint>& endpoints) {
  if (state_ != kVerified) {
    LOG(kError) << "Not connected to LifeStuffManager.";
    return false;
  }

  endpoints = bootstrap_nodes_;
  return true;
}

bool ClientController::FindNextAcceptingPort(TransportPtr request_transport) {
  int result(1);
  Port manager_port(lifestuff_manager_port_);
  request_transport->Connect(manager_port, result);
  while (result != kSuccess) {
    ++manager_port;
    if (manager_port > lifestuff_manager_port_ + LifeStuffManager::kMaxRangeAboveDefaultPort()) {
      LOG(kError) << "ClientController failed to connect to LifeStuffManager on all ports in range "
                  << lifestuff_manager_port_ << " to "
                  << lifestuff_manager_port_ + LifeStuffManager::kMaxRangeAboveDefaultPort();
      return false;
    }
    request_transport->Connect(manager_port, result);
  }
  lifestuff_manager_port_ = manager_port;
  return true;
}

bool ClientController::ConnectToLifeStuffManager(std::string& path_to_new_installer) {
  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  std::mutex mutex;
  std::condition_variable condition_variable;
  State state(kInitialising);

  request_transport->on_message_received().connect(
      [&mutex, &condition_variable, &state, &path_to_new_installer, this]
      (const std::string& message, Port lifestuff_manager_port) {
        HandleRegisterResponse(message, lifestuff_manager_port, mutex, condition_variable, state,
                               path_to_new_installer);
      });
  request_transport->on_error().connect(
      [&mutex, &condition_variable, &state] (const int& error) {
        std::unique_lock<std::mutex> lock(mutex);
        state = kFailed;
        condition_variable.notify_one();
        LOG(kError) << "Transport reported error code " << error;
      });
  while (FindNextAcceptingPort(request_transport)) {
    protobuf::ClientRegistrationRequest request;
    request.set_listening_port(local_port_);
    request.set_version(VersionToInt(kApplicationVersion));
    request_transport->Send(detail::WrapMessage(MessageType::kClientRegistrationRequest,
                                                request.SerializeAsString()),
                            lifestuff_manager_port_);
    LOG(kVerbose) << "Sending registration request to port " << lifestuff_manager_port_;
    {
      std::unique_lock<std::mutex> lock(mutex);
      if (!condition_variable.wait_for(lock,
                                       std::chrono::seconds(3),
                                       [&state] { return state != kInitialising; })) {
        LOG(kError) << "Timed out waiting for ClientController initialisation.";
      } else {
        break;
      }
    }
  }

  if (state != kVerified) {
    LOG(kError) << "ClientController is uninitialised.";
    return false;
  }

  return true;
}

void ClientController::HandleRegisterResponse(const std::string& message,
                                              Port /*lifestuff_manager_port*/,
                                              std::mutex& mutex,
                                              std::condition_variable& condition_variable,
                                              State& state,
                                              std::string& path_to_new_installer) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    std::unique_lock<std::mutex> lock(mutex);
    state = kFailed;
    condition_variable.notify_one();
    return;
  }
  protobuf::ClientRegistrationResponse response;
  if (!response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse ClientRegistrationResponse.";
    std::unique_lock<std::mutex> lock(mutex);
    state = kFailed;
    condition_variable.notify_one();
    return;
  }

//  if (response.bootstrap_endpoint_ip_size() == 0 ||
//      response.bootstrap_endpoint_port_size() == 0) {
//    LOG(kError) << "Response has no bootstrap nodes.";
//    std::unique_lock<std::mutex> lock(mutex);
//    state = kFailed;
//    condition_variable.notify_one();
//    return;
//  }

  if (response.has_path_to_new_installer()) {
    boost::system::error_code error_code;
    fs::path new_version(response.path_to_new_installer());
    if (!fs::exists(new_version, error_code) || error_code) {
      LOG(kError) << "New version file missing: " << new_version;
    } else {
      path_to_new_installer = new_version.string();
    }
  }

  int max_index(response.bootstrap_endpoint_ip_size() >
                response.bootstrap_endpoint_port_size() ?
                    response.bootstrap_endpoint_port_size() :
                    response.bootstrap_endpoint_ip_size());
  for (int n(0); n < max_index; ++n) {
    bootstrap_nodes_.push_back(std::make_pair(response.bootstrap_endpoint_ip(n),
                                              response.bootstrap_endpoint_port(n)));
  }

  LOG(kSuccess) << "Successfully registered with LifeStuffManager on port "
                << lifestuff_manager_port_;
  std::lock_guard<std::mutex> lock(mutex);
  state = kVerified;
  condition_variable.notify_one();
}

bool ClientController::StartVault(const Fob& fob,
                                  const std::string& account_name,
                                  const fs::path& chunkstore) {
  if (state_ != kVerified) {
    LOG(kError) << "Not connected to LifeStuffManager.";
    return false;
  }

  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false), local_result(false);
  protobuf::StartVaultRequest start_vault_request;
  start_vault_request.set_account_name(account_name);
  start_vault_request.set_fob(SerialiseFob(fob).string());
  asymm::PlainText token(maidsafe::RandomString(16));
  start_vault_request.set_token(token.string());
  start_vault_request.set_token_signature(asymm::Sign(token, fob.private_key()).string());
  start_vault_request.set_credential_change(false);
  start_vault_request.set_client_port(local_port_);
  if (!chunkstore.empty())
    start_vault_request.set_chunkstore_path(chunkstore.string());
  std::function<void(bool)> callback =                                            // NOLINT (Fraser)
    [&](bool result) {
      std::lock_guard<std::mutex> lock(local_mutex);
      local_result = result;
      done = true;
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
      [this, callback](const std::string& message, Port /*lifestuff_manager_port*/) {
        HandleStartStopVaultResponse<protobuf::StartVaultResponse>(message, callback);
      });
  request_transport->on_error().connect([this, callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback(false);
  });

  LOG(kVerbose) << "Sending request to start vault to port " << lifestuff_manager_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kStartVaultRequest,
                                              start_vault_request.SerializeAsString()),
                          lifestuff_manager_port_);
  {
    std::unique_lock<std::mutex> local_lock(local_mutex);
    if (!local_cond_var.wait_for(local_lock, std::chrono::seconds(10), [&done] { return done; })) {
      LOG(kError) << "Timed out waiting for reply.";
      return false;
    }
    if (!local_result) {
      LOG(kError) << "Failed starting vault.";
      return false;
    }
  }

  std::unique_lock<std::mutex> lock(joining_vaults_mutex_);
  joining_vaults_[fob.identity()] = false;
  if (!joining_vaults_conditional_.wait_for(lock,
                                            std::chrono::minutes(1),
                                            [&] { return joining_vaults_[fob.identity()]; })) {
    LOG(kError) << "Timed out waiting for vault join confirmation.";
    return false;
  }
  joining_vaults_.erase(fob.identity());

  return true;
}

bool ClientController::StopVault(const asymm::PlainText& data,
                                 const asymm::Signature& signature,
                                 const Identity& identity) {
  if (state_ != kVerified) {
    LOG(kError) << "Not connected to LifeStuffManager.";
    return false;
  }

  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false), local_result(false);
  protobuf::StopVaultRequest stop_vault_request;
  stop_vault_request.set_data(data.string());
  stop_vault_request.set_signature(signature.string());
  stop_vault_request.set_identity(identity.string());

  std::function<void(bool)> callback =                                            // NOLINT (Fraser)
    [&](bool result) {
      std::lock_guard<std::mutex> lock(local_mutex);
      local_result = result;
      done = true;
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
      [this, callback](const std::string& message, Port /*lifestuff_manager_port*/) {
        HandleStartStopVaultResponse<protobuf::StopVaultResponse>(message, callback);
      });
  request_transport->on_error().connect([this, callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback(false);
  });

  LOG(kVerbose) << "Sending request to stop vault to port " << lifestuff_manager_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kStopVaultRequest,
                                              stop_vault_request.SerializeAsString()),
                          lifestuff_manager_port_);

  std::unique_lock<std::mutex> lock(local_mutex);
  if (!local_cond_var.wait_for(lock, std::chrono::seconds(10), [&] { return done; })) {
    LOG(kError) << "Timed out waiting for reply.";
    return false;
  }
  if (!local_result)
    LOG(kError) << "Failed stopping vault.";
  return local_result;
}

template<typename ResponseType>
void ClientController::HandleStartStopVaultResponse(const std::string& message,
                                                    const std::function<void(bool)>& callback) {  // NOLINT
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    callback(false);
    return;
  }

  ResponseType vault_response;
  if (!vault_response.ParseFromString(payload)) {
    LOG(kError) << "Failed to parse response.";
    callback(false);
    return;
  }

  callback(vault_response.result());
}

bool ClientController::SetUpdateInterval(const bptime::seconds& update_interval) {
  if (update_interval < LifeStuffManager::kMinUpdateInterval() ||
      update_interval > LifeStuffManager::kMaxUpdateInterval()) {
    LOG(kError) << "Cannot set update interval to " << update_interval << "  It must be in range ["
                << LifeStuffManager::kMinUpdateInterval() << ", "
                << LifeStuffManager::kMaxUpdateInterval() << "]";
    return false;
  }
  return SetOrGetUpdateInterval(update_interval) == update_interval;
}

bptime::time_duration ClientController::GetUpdateInterval() {
  return SetOrGetUpdateInterval(bptime::pos_infin);
}

bptime::time_duration ClientController::SetOrGetUpdateInterval(
      const bptime::time_duration& update_interval) {
  if (state_ != kVerified) {
    LOG(kError) << "Not connected to LifeStuffManager.";
    return bptime::pos_infin;
  }

  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bptime::time_duration returned_result(bptime::neg_infin);
  protobuf::UpdateIntervalRequest update_interval_request;
  if (!update_interval.is_pos_infinity())
    update_interval_request.set_new_update_interval(update_interval.total_seconds());

  std::function<void(bptime::time_duration)> callback =
      [&](bptime::time_duration update_interval) {
        std::lock_guard<std::mutex> lock(local_mutex);
        returned_result = update_interval;
        local_cond_var.notify_one();
      };

  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  int result(0);
  request_transport->Connect(lifestuff_manager_port_, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to LifeStuffManager.";
      return bptime::pos_infin;
  }
  request_transport->on_message_received().connect(
      [this, callback](const std::string& message, Port /*lifestuff_manager_port*/) {
        HandleUpdateIntervalResponse(message, callback);
      });
  request_transport->on_error().connect([this, callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback(bptime::pos_infin);
  });

  std::unique_lock<std::mutex> lock(local_mutex);
  LOG(kVerbose) << "Sending request to " << (update_interval.is_pos_infinity() ? "get" : "set")
                << " update interval to LifeStuffManager on port " << lifestuff_manager_port_;
  request_transport->Send(detail::WrapMessage(MessageType::kUpdateIntervalRequest,
                                              update_interval_request.SerializeAsString()),
                          lifestuff_manager_port_);

  if (!local_cond_var.wait_for(lock,
                               std::chrono::seconds(10),
                               [&] {
                                 return !returned_result.is_neg_infinity();
                               })) {
    LOG(kError) << "Timed out waiting for reply.";
    return bptime::pos_infin;
  }

  if (returned_result.is_pos_infinity())
    LOG(kError) << "Failed to " << (update_interval.is_pos_infinity() ? "get" : "set")
                << " update interval.";
  return returned_result;
}

bool ClientController::GetBootstrapNodes(
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

void ClientController::HandleBootstrapResponse(const std::string& message,
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
  bootstrap_nodes_ = bootstrap_endpoints;
  callback(true);
}

void ClientController::HandleUpdateIntervalResponse(
    const std::string& message,
    const std::function<void(bptime::time_duration)>& callback) {  // NOLINT
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    callback(bptime::pos_infin);
    return;
  }

  protobuf::UpdateIntervalResponse update_interval_response;
  if (!update_interval_response.ParseFromString(payload) ||
      !update_interval_response.IsInitialized()) {
    LOG(kError) << "Failed to parse UpdateIntervalResponse.";
    callback(bptime::pos_infin);
    return;
  }

  if (update_interval_response.update_interval() == 0) {
    LOG(kError) << "UpdateIntervalResponse indicates failure.";
    callback(bptime::pos_infin);
  } else {
    callback(bptime::seconds(update_interval_response.update_interval()));
  }
}

void ClientController::HandleReceivedRequest(const std::string& message, Port peer_port) {
  /*assert(peer_port == lifestuff_manager_port_);*/  // LifeStuffManager does not currently use
                                               // its established port to contact ClientController
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }
  LOG(kVerbose) << "HandleReceivedRequest: message type " << static_cast<int>(type) << " received.";
  std::string response;
  switch (type) {
    case MessageType::kNewVersionAvailable:
      HandleNewVersionAvailable(payload, response);
      break;
    case MessageType::kVaultJoinConfirmation:
      HandleVaultJoinConfirmation(payload, response);
      break;
    default:
      return;
  }
  receiving_transport_->Send(response, peer_port);
}

void ClientController::HandleNewVersionAvailable(const std::string& request,
                                                 std::string& response) {
  protobuf::NewVersionAvailable new_version_available;
  protobuf::NewVersionAvailableAck new_version_available_ack;
  if (!new_version_available.ParseFromString(request)) {
    LOG(kError) << "Failed to parse NewVersionAvailable.";
    new_version_available_ack.set_new_version_filepath("");
  } else {
    boost::system::error_code error_code;
    fs::path new_version(new_version_available.new_version_filepath());
    if (!fs::exists(new_version, error_code) || error_code) {
      LOG(kError) << "New version file missing: " << new_version;
      new_version_available_ack.set_new_version_filepath("");
    } else {
      new_version_available_ack.set_new_version_filepath(
          new_version_available.new_version_filepath());
    }
  }
  response = detail::WrapMessage(MessageType::kNewVersionAvailableAck,
                                 new_version_available_ack.SerializeAsString());
  on_new_version_available_(NonEmptyString(new_version_available.new_version_filepath()));
}

void ClientController::HandleVaultJoinConfirmation(const std::string& request,
                                                   std::string& response) {
  protobuf::VaultJoinConfirmation vault_join_confirmation;
  protobuf::VaultJoinConfirmationAck vault_join_confirmation_ack;
  if (!vault_join_confirmation.ParseFromString(request)) {
    LOG(kError) << "Failed to parse VaultJoinConfirmation.";
    vault_join_confirmation_ack.set_ack(false);
  } else {
    Identity identity(vault_join_confirmation.identity());
    std::unique_lock<std::mutex> lock(joining_vaults_mutex_);
    if (joining_vaults_.find(identity) == joining_vaults_.end()) {
      LOG(kError) << "Identity is not in list of joining vaults.";
      vault_join_confirmation_ack.set_ack(false);
    } else {
      joining_vaults_[identity] = true;
      joining_vaults_conditional_.notify_all();
      vault_join_confirmation_ack.set_ack(true);
    }
  }
  response = detail::WrapMessage(MessageType::kVaultJoinConfirmationAck,
                                 vault_join_confirmation_ack.SerializeAsString());
}

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe
