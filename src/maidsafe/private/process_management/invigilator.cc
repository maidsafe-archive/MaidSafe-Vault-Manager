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

#include "maidsafe/private/process_management/invigilator.h"

#include <chrono>
#include <iostream>

#include "boost/filesystem/path.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/process_management/controller_messages_pb.h"
#include "maidsafe/private/process_management/local_tcp_transport.h"
#include "maidsafe/private/process_management/utils.h"
#include "maidsafe/private/process_management/vault_info_pb.h"


namespace bptime = boost::posix_time;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace process_management {

Invigilator::VaultInfo::VaultInfo()
    : process_index(),
      account_name(),
      keys(),
      chunkstore_path(),
      vault_port(0),
      client_port(0),
      requested_to_run(false),
      joined_network(false) {}

void Invigilator::VaultInfo::ToProtobuf(protobuf::VaultInfo* pb_vault_info) const {
  pb_vault_info->set_account_name(account_name);
  std::string serialized_keys;
  asymm::SerialiseKeys(keys, serialized_keys);
  pb_vault_info->set_keys(serialized_keys);
  pb_vault_info->set_chunkstore_path(chunkstore_path);
  pb_vault_info->set_requested_to_run(requested_to_run);
}

void Invigilator::VaultInfo::FromProtobuf(const protobuf::VaultInfo& pb_vault_info) {
  account_name = pb_vault_info.account_name();
  asymm::ParseKeys(pb_vault_info.keys(), keys);
  chunkstore_path = pb_vault_info.chunkstore_path();
  requested_to_run = pb_vault_info.requested_to_run();
}


Invigilator::Invigilator()
    : process_manager_(),
#ifdef USE_TEST_KEYS
      download_manager_("http", "dash.maidsafe.net", "~phil/tests/test_vault_manager"),
#else
      // TODO(Fraser#5#): 2012-08-12 - Provide proper path to server as constants
      download_manager_("http", "dash.maidsafe.net", "~phil"),
#endif
      asio_service_(3),
      update_interval_(/*bptime::hours(24)*/ kMinUpdateInterval()),
      update_timer_(asio_service_.service()),
      update_mutex_(),
      transport_(new LocalTcpTransport(asio_service_.service())),
      local_port_(kMinPort()),
      vault_infos_(),
      vault_infos_mutex_(),
      client_ports_(),
      client_ports_mutex_(),
#ifdef USE_TEST_KEYS
      config_file_path_(fs::path(".") / detail::kGlobalConfigFilename) {
#else
      config_file_path_(GetSystemAppSupportDir() / detail::kGlobalConfigFilename) {
#endif
  boost::system::error_code error_code;
  if (!fs::exists(config_file_path_, error_code) ||
      error_code.value() == boost::system::errc::no_such_file_or_directory) {
    LOG(kInfo) << "Invigilator failed to find existing config file in " << config_file_path_;
    if (!CreateConfigFile()) {
      LOG(kError) << "Invigilator failed to create new config file at " << config_file_path_
                  << ". Shutting down.";
      return;
    }
  }
  UpdateExecutor();

  LOG(kInfo) << "Invigilator started";
  asio_service_.Start();
  transport_->on_message_received().connect(
      [this] (const std::string& message, Port peer_port) {
        HandleReceivedMessage(message, peer_port);
      });
  transport_->on_error().connect([] (const int& error) {
                                   LOG(kError) << "Transport reported error code: " << error;
                                 });

  if (!ListenForMessages()) {
    LOG(kError) << "Invigilator failed to create a listening port. Shutting down.";
    return;
  }

  ReadConfigFileAndStartVaults();
  CheckForUpdates(error_code);
}

Invigilator::~Invigilator() {
  process_manager_.LetAllProcessesDie();
  StopAllVaults();
  {
    std::lock_guard<std::mutex> lock(update_mutex_);
    update_timer_.cancel();
  }
  transport_->StopListeningAndCloseConnections();
  asio_service_.Stop();
}

boost::posix_time::time_duration Invigilator::kMinUpdateInterval() {
  return bptime::minutes(5);
}

boost::posix_time::time_duration Invigilator::kMaxUpdateInterval() {
  return bptime::hours(24 * 7);
}

void Invigilator::RestartInvigilator(const std::string& latest_file,
                                     const std::string& executable_name) const {
  // TODO(Fraser#5#): 2012-08-12 - Define command in constant.  Do we need 2 shell scripts?
  //                               Do we need 2 parameters to unix script?
#ifdef MAIDSAFE_WIN32
  std::string command("restart_vm_windows.bat " + latest_file + " " + executable_name);
#else
  std::string command("./restart_vm_linux.sh " + latest_file + " " + executable_name);
#endif
  // system("/etc/init.d/mvm restart");
  int result(system(command.c_str()));
  if (result != 0)
    LOG(kWarning) << "Result: " << result;
}

bool Invigilator::CreateConfigFile() {
  protobuf::InvigilatorConfig config;
  config.set_update_interval(update_interval_.total_seconds());

  std::string s_major(APPLICATION_VERSION_MAJOR);
  std::string s_minor(APPLICATION_VERSION_MINOR);
  std::string s_patch(APPLICATION_VERSION_PATCH);
  config.set_latest_local_version(s_major + "." + s_minor + "." + s_patch);

  if (!ObtainBootstrapInformation(config)) {
    LOG(kError) << "Failed to obtain bootstrap information from server.";
    return false;
  }

  if (!WriteFile(config_file_path_, config.SerializeAsString())) {
    LOG(kError) << "Failed to create config file " << config_file_path_;
    return false;
  }
  LOG(kInfo) << "Created config file " << config_file_path_;

  download_manager_.SetLatestLocalVersion(config.latest_local_version());

  return true;
}

bool Invigilator::ReadConfigFileAndStartVaults() {
  std::string content;
  if (!ReadFile(config_file_path_, &content)) {
    LOG(kError) << "Failed to read config file " << config_file_path_;
    return false;
  }

  protobuf::InvigilatorConfig config;
  if (!config.ParseFromString(content)) {
    LOG(kError) << "Failed to parse config file " << config_file_path_;
    return false;
  }

  download_manager_.SetLatestLocalVersion(config.latest_local_version());
  update_interval_ = bptime::seconds(config.update_interval());

  for (int i(0); i != config.vault_info_size(); ++i) {
    VaultInfoPtr vault_info(new VaultInfo);
    vault_info->FromProtobuf(config.vault_info(i));
    if (vault_info->requested_to_run) {
      if (!StartVaultProcess(vault_info))
        LOG(kError) << "Failed to start vault ID" << Base64Substr(vault_info->keys.identity);
    }
  }

  return true;
}

bool Invigilator::WriteConfigFile() {
  protobuf::InvigilatorConfig config;
  {
    std::lock_guard<std::mutex> lock(update_mutex_);
    config.set_update_interval(update_interval_.total_seconds());
  }
  config.set_latest_local_version(download_manager_.latest_local_version());
  {
    std::lock_guard<std::mutex> lock(vault_infos_mutex_);
    for (auto& vault_info : vault_infos_) {
      protobuf::VaultInfo* pb_vault_info = config.add_vault_info();
      vault_info->ToProtobuf(pb_vault_info);
    }
  }
  if (!WriteFile(config_file_path_, config.SerializeAsString())) {
    LOG(kError) << "Failed to write config file " << config_file_path_;
    return false;
  }
  return true;
}

bool Invigilator::ListenForMessages() {
  int result(0);
  transport_->StartListening(local_port_, result);
  while (result != kSuccess) {
    ++local_port_;
    if (local_port_ > kMaxPort()) {
      LOG(kError) << "Listening failed on all ports in range " << kMinPort() << " - " << kMaxPort();
      return false;
    }
    transport_->StartListening(local_port_, result);
  }

  return true;
}

void Invigilator::HandleReceivedMessage(const std::string& message, Port peer_port) {
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }

  LOG(kVerbose) << "HandleReceivedMessage: message type " << static_cast<int>(type) << " received.";
  std::string response;
  switch (type) {
    case MessageType::kClientRegistrationRequest:
      HandleClientRegistrationRequest(payload, response);
      break;
    case MessageType::kStartVaultRequest:
      HandleStartVaultRequest(payload, response);
      break;
    case MessageType::kVaultIdentityRequest:
      HandleVaultIdentityRequest(payload, response);
      break;
    case MessageType::kVaultJoinedNetwork:
      HandleVaultJoinedNetworkRequest(payload, response);
      break;
    case MessageType::kStopVaultRequest:
      HandleStopVaultRequest(payload, response);
      break;
    case MessageType::kUpdateIntervalRequest:
      HandleUpdateIntervalRequest(payload, response);
      break;
    case MessageType::kSendEndpointToInvigilatorRequest:
      HandleSendEndpointToInvigilatorRequest(payload, response);
      break;
    case MessageType::kBootstrapRequest:
      HandleBootstrapRequest(payload, response);
      break;
    default:
      return;
  }
  transport_->Send(response, peer_port);
}

void Invigilator::HandleClientRegistrationRequest(const std::string& request,
                                                  std::string& response) {
  protobuf::ClientRegistrationRequest client_request;
  if (!client_request.ParseFromString(request)) {  // Silently drop
    LOG(kError) << "Failed to parse client registration request.";
    return;
  }

  {
    std::lock_guard<std::mutex> lock(client_ports_mutex_);
    uint16_t request_port(static_cast<uint16_t>(client_request.listening_port()));
    auto itr(std::find_if(client_ports_.begin(),
                          client_ports_.end(),
                          [&request_port] (const uint16_t &element)->bool {
                            return element == request_port;
                          }));
    if (itr == client_ports_.end())
      client_ports_.push_back(request_port);
  }

  protobuf::ClientRegistrationResponse client_response;
  protobuf::InvigilatorConfig config;
  std::vector<EndPoint> endpoints;
  if (ReadBootstrapEndpoints(config, endpoints) || !endpoints.empty()) {
    std::for_each(endpoints.begin(),
                  endpoints.end(),
                  [&client_response] (const EndPoint& element) {
                    client_response.add_bootstrap_endpoint_ip(element.first);
                    client_response.add_bootstrap_endpoint_port(element.second);
                  });
  }

  response = detail::WrapMessage(MessageType::kClientRegistrationResponse,
                                 client_response.SerializeAsString());
}

void Invigilator::HandleStartVaultRequest(const std::string& request, std::string& response) {
  protobuf::StartVaultRequest start_vault_request;
  if (!start_vault_request.ParseFromString(request)) {
    // Silently drop
    LOG(kError) << "Failed to parse StartVaultRequest.";
    return;
  }

  auto set_response([&response] (bool result) {
    protobuf::StartVaultResponse start_vault_response;
    start_vault_response.set_result(result);
    response = detail::WrapMessage(MessageType::kStartVaultResponse,
                                   start_vault_response.SerializeAsString());
  });

  uint16_t client_port(static_cast<uint16_t>(start_vault_request.client_port()));
  auto itr(std::find_if(client_ports_.begin(),
                      client_ports_.end(),
                      [&client_port] (const uint16_t &element)->bool {
                        return element == client_port;
                      }));
  if (itr == client_ports_.end()) {
    LOG(kError) << "Client is not registered with Invigilator.";
    return set_response(false);
  }

  VaultInfoPtr vault_info(new VaultInfo);
  {
    std::lock_guard<std::mutex> lock(vault_infos_mutex_);
    auto itr(FindFromIdentity(vault_info->keys.identity));
    bool existing_vault(false);
    if (itr != vault_infos_.end()) {
      existing_vault = true;
      if (kSuccess != asymm::CheckSignature(start_vault_request.token(),
                                            start_vault_request.token_signature(),
                                            vault_info->keys.public_key)) {
        LOG(kError) << "Communication from someone that does not validate as owner.";
        return set_response(false);  // TODO(Team): Drop silienty?
      }

      if (!start_vault_request.credential_change()) {
        if (!(*itr)->joined_network) {
          (*itr)->client_port = client_port;
          (*itr)->requested_to_run = true;
          process_manager_.StartProcess((*itr)->process_index);
        }
      } else {
        asymm::Keys temp_keys;
        if (!asymm::ParseKeys(start_vault_request.keys(), temp_keys)) {
          LOG(kError) << "Keys provided do not parse.";
          return set_response(false);
        }
        if ((*itr)->joined_network) {
          // TODO(Team): Stop and restart with new credentials
        } else {
          // TODO(Team): Start with new credentials
          (*itr)->account_name = start_vault_request.account_name();
          (*itr)->keys = temp_keys;
          (*itr)->client_port = client_port;
          (*itr)->requested_to_run = true;
        }
      }
    } else {
      // The vault is not already registered.
      if (!asymm::ParseKeys(start_vault_request.keys(), vault_info->keys)) {
        LOG(kError) << "Keys provided do not parse.";
        return set_response(false);
      }
      vault_info->account_name = start_vault_request.account_name();
      std::string short_vault_id(EncodeToBase64(crypto::Hash<crypto::SHA1>(
                                                    vault_info->keys.identity)));
      vault_info->chunkstore_path = (config_file_path_.parent_path() / short_vault_id).string();
      vault_info->client_port = client_port;
      if (!StartVaultProcess(vault_info)) {
        LOG(kError) << "Failed to start a process for vault ID: "
                    << Base64Substr(vault_info->keys.identity);
        return set_response(false);
      }
    }
    if (!AmendVaultDetailsInConfigFile(vault_info, existing_vault)) {
      LOG(kError) << "Failed to amend details in config file for vault ID: "
                  << Base64Substr(vault_info->keys.identity);
      return set_response(false);
    }
  }

  set_response(true);
}

void Invigilator::HandleVaultIdentityRequest(const std::string& request, std::string& response) {
  protobuf::VaultIdentityRequest vault_identity_request;
  if (!vault_identity_request.ParseFromString(request)) {
    // Silently drop
    LOG(kError) << "Failed to parse VaultIdentityRequest.";
    return;
  }

  protobuf::VaultIdentityResponse vault_identity_response;
  std::lock_guard<std::mutex> lock(vault_infos_mutex_);
  auto itr(FindFromProcessIndex(vault_identity_request.process_index()));
  if (itr == vault_infos_.end()) {
    LOG(kError) << "Vault with process_index " << vault_identity_request.process_index()
                << " hasn't been added.";
    vault_identity_response.set_account_name("");
    vault_identity_response.set_keys("");
    // TODO(Team): Should this be dropped silently?
  } else {
    std::string serialised_keys;
    if (!asymm::SerialiseKeys((*itr)->keys, serialised_keys)) {
      LOG(kError) << "Failed to serialise keys of vault with process_index "
                  << vault_identity_request.process_index();
      vault_identity_response.set_account_name("");
      vault_identity_response.set_keys("");
      // TODO(Team): Should this be informed with more detail?
    } else {
      protobuf::InvigilatorConfig config;
      std::vector<EndPoint> endpoints;
      if (!ReadBootstrapEndpoints(config, endpoints) || endpoints.empty()) {
        if (!ObtainBootstrapInformation(config)) {
          LOG(kError) << "Failed to get endpoints for process_index "
                      << vault_identity_request.process_index();
          vault_identity_response.set_account_name("");
          vault_identity_response.set_keys("");
        } else {
          if (!ReadBootstrapEndpoints(config, endpoints)) {
            LOG(kError) << "Failed to read endpoints obtained from server.";
            vault_identity_response.set_account_name("");
            vault_identity_response.set_keys("");
          }
        }
      } else {
        itr = FindFromProcessIndex(vault_identity_request.process_index());
        vault_identity_response.set_account_name((*itr)->account_name);
        vault_identity_response.set_keys(serialised_keys);
        vault_identity_response.set_chunkstore_path((*itr)->chunkstore_path);
        (*itr)->vault_port = static_cast<uint16_t>(vault_identity_request.listening_port());
        std::for_each(endpoints.begin(),
                      endpoints.end(),
                      [&vault_identity_response] (const EndPoint& element) {
                        vault_identity_response.add_bootstrap_endpoint_ip(element.first);
                        vault_identity_response.add_bootstrap_endpoint_port(element.second);
                      });
      }
    }
  }

  response = detail::WrapMessage(MessageType::kVaultIdentityResponse,
                                 vault_identity_response.SerializeAsString());
}

void Invigilator::HandleVaultJoinedNetworkRequest(const std::string& request,
                                                  std::string& response) {
  protobuf::VaultJoinedNetwork vault_joined_network;
  if (!vault_joined_network.ParseFromString(request)) {
    // Silently drop
    LOG(kError) << "Failed to parse VaultJoinedNetwork.";
    return;
  }

  protobuf::VaultJoinedNetworkAck vault_joined_network_ack;
  std::lock_guard<std::mutex> lock(vault_infos_mutex_);
  auto itr(FindFromProcessIndex(vault_joined_network.process_index()));
  bool join_result(false);
  if (itr == vault_infos_.end()) {
    LOG(kError) << "Vault with process_index " << vault_joined_network.process_index()
                << " hasn't been added.";
    join_result = false;
  } else {
    join_result = true;
    (*itr)->joined_network = vault_joined_network.joined();
  }
  vault_joined_network_ack.set_ack(join_result);
  if ((*itr)->client_port != 0)
  SendVaultJoinConfirmation((*itr)->keys.identity, join_result);
  response = detail::WrapMessage(MessageType::kVaultIdentityResponse,
                                 vault_joined_network_ack.SerializeAsString());
}

void Invigilator::HandleStopVaultRequest(const std::string& request, std::string& response) {
  protobuf::StopVaultRequest stop_vault_request;
  if (!stop_vault_request.ParseFromString(request)) {
    // Silently drop
    LOG(kError) << "Failed to parse StopVaultRequest.";
    return;
  }

  protobuf::StopVaultResponse stop_vault_response;
  std::lock_guard<std::mutex> lock(vault_infos_mutex_);
  auto itr(FindFromIdentity(stop_vault_request.identity()));
  if (itr == vault_infos_.end()) {
    LOG(kError) << "Vault with identity " << Base64Substr(stop_vault_request.identity())
                << " hasn't been added.";
    stop_vault_response.set_result(false);
  } else if (kSuccess != asymm::CheckSignature(stop_vault_request.data(),
                                               stop_vault_request.signature(),
                                               (*itr)->keys.public_key)) {
    LOG(kError) << "Failure to validate request to stop vault ID "
                << Base64Substr(stop_vault_request.identity());
    stop_vault_response.set_result(false);
  } else {
    LOG(kInfo) << "Shutting down vault with identity "
               << Base64Substr(stop_vault_request.identity());
    stop_vault_response.set_result(StopVault(stop_vault_request.identity(),
                                             stop_vault_request.data(),
                                             stop_vault_request.signature(),
                                             true));
    if (!AmendVaultDetailsInConfigFile(*itr, true)) {
      LOG(kError) << "Failed to amend details in config file for vault ID: "
                  << Base64Substr((*itr)->keys.identity);
      stop_vault_response.set_result(false);
    }
  }
  response = detail::WrapMessage(MessageType::kStopVaultResponse,
                                 stop_vault_response.SerializeAsString());
}

void Invigilator::HandleUpdateIntervalRequest(const std::string& request, std::string& response) {
  protobuf::UpdateIntervalRequest update_interval_request;
  if (!update_interval_request.ParseFromString(request)) {  // Silently drop
    LOG(kError) << "Failed to parse UpdateIntervalRequest.";
    return;
  }

  protobuf::UpdateIntervalResponse update_interval_response;
  if (update_interval_request.has_new_update_interval()) {
    if (SetUpdateInterval(bptime::seconds(update_interval_request.new_update_interval())))
      update_interval_response.set_update_interval(GetUpdateInterval().total_seconds());
    else
      update_interval_response.set_update_interval(0);
  } else {
    update_interval_response.set_update_interval(GetUpdateInterval().total_seconds());
  }

  response = detail::WrapMessage(MessageType::kUpdateIntervalResponse,
                                 update_interval_response.SerializeAsString());
}

void Invigilator::HandleSendEndpointToInvigilatorRequest(const std::string& request,
                                                         std::string& response) {
  protobuf::SendEndpointToInvigilatorRequest send_endpoint_request;
  protobuf::SendEndpointToInvigilatorResponse send_endpoint_response;
  if (!send_endpoint_request.ParseFromString(request)) {
    LOG(kError) << "Failed to parse SendEndpointToInvigilator.";
    return;
  }
  if (AddBootstrapEndPoint(
          send_endpoint_request.bootstrap_endpoint_ip(),
          static_cast<uint16_t>(send_endpoint_request.bootstrap_endpoint_port()))) {
    send_endpoint_response.set_result(true);
  } else {
    send_endpoint_response.set_result(false);
  }
  response = detail::WrapMessage(MessageType::kSendEndpointToInvigilatorResponse,
                                 send_endpoint_response.SerializeAsString());
}

void Invigilator::HandleBootstrapRequest(const std::string& request, std::string& response) {
  protobuf::BootstrapRequest bootstrap_request;
  protobuf::BootstrapResponse bootstrap_response;
  if (!bootstrap_request.ParseFromString(request)) {
    LOG(kError) << "Failed to parse BootstrapRequest.";
    return;
  }
  protobuf::InvigilatorConfig config;
  std::vector<EndPoint> endpoints;
  if (!ReadBootstrapEndpoints(config, endpoints) || endpoints.empty()) {
    if (!ObtainBootstrapInformation(config)) {
      LOG(kError) << "Failed to get endpoints for message_id "
                  << bootstrap_request.message_id();
    } else {
      if (!ReadBootstrapEndpoints(config, endpoints)) {
        LOG(kError) << "Failed to read endpoints obtained from server.";
      }
    }
  } else {
    std::for_each(endpoints.begin(),
                  endpoints.end(),
                  [&bootstrap_response] (const EndPoint& element) {
                    bootstrap_response.add_bootstrap_endpoint_ip(element.first);
                    bootstrap_response.add_bootstrap_endpoint_port(element.second);
                  });
  }
  response = detail::WrapMessage(MessageType::kBootstrapResponse,
                                 bootstrap_response.SerializeAsString());
}

bool Invigilator::SetUpdateInterval(const bptime::time_duration& update_interval) {
  if (update_interval < kMinUpdateInterval() || update_interval > kMaxUpdateInterval()) {
    LOG(kError) << "Invalid update interval of " << update_interval;
    return false;
  }
  std::lock_guard<std::mutex> lock(update_mutex_);
  update_interval_ = update_interval;
  update_timer_.expires_from_now(update_interval_);
  update_timer_.async_wait([this] (const boost::system::error_code& ec) { CheckForUpdates(ec); });  // NOLINT (Fraser)
  return true;
}

bptime::time_duration Invigilator::GetUpdateInterval() const {
  std::lock_guard<std::mutex> lock(update_mutex_);
  return update_interval_;
}

void Invigilator::CheckForUpdates(const boost::system::error_code& ec) {
  if (ec) {
    if (ec != boost::asio::error::operation_aborted)
      LOG(kError) << ec.message();
    return;
  }

  UpdateExecutor();

  update_timer_.expires_from_now(update_interval_);
  update_timer_.async_wait([this] (const boost::system::error_code& ec) { CheckForUpdates(ec); });  // NOLINT (Fraser)
}

// NOTE: vault_info_mutex_ must be locked when calling this function.
void Invigilator::SendVaultJoinConfirmation(const std::string& identity, bool join_result) {
  protobuf::VaultJoinConfirmation vault_join_confirmation;
  auto itr(FindFromIdentity(identity));
  if (itr == vault_infos_.end()) {
    LOG(kError) << "Vault with identity " << Base64Substr(identity)
                << " hasn't been added.";
    return;
  }
  uint16_t client_port((*itr)->client_port);
  std::mutex local_mutex;
  std::condition_variable local_cond_var;
  bool done(false), local_result(false);
  std::function<void(bool)> callback =                                            // NOLINT (Fraser)
    [&](bool result) {
      std::lock_guard<std::mutex> lock(local_mutex);
      local_result = result;
      done = true;
      local_cond_var.notify_one();
    };
  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
  int result(0);
  request_transport->Connect((*itr)->client_port, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect request transport to client.";
    callback(false);
  }
  request_transport->on_message_received().connect(
      [this, callback](const std::string& message, Port /*invigilator_port*/) {
        HandleVaultJoinConfirmationAck(message, callback);
      });
  request_transport->on_error().connect([this, callback](const int& error) {
    LOG(kError) << "Transport reported error code " << error;
    callback(false);
  });
  vault_join_confirmation.set_identity(identity);
  vault_join_confirmation.set_joined(join_result);
  LOG(kVerbose) << "Sending vault join confirmation to client on port " << (*itr)->client_port;
  request_transport->Send(detail::WrapMessage(MessageType::kVaultJoinConfirmation,
                                              vault_join_confirmation.SerializeAsString()),
                          client_port);

  std::unique_lock<std::mutex> lock(local_mutex);
  if (!local_cond_var.wait_for(lock, std::chrono::seconds(10), [&] { return done; }))
    LOG(kError) << "Timed out waiting for reply.";
  if (!local_result)
    LOG(kError) << "Failed to confirm joining of vault to client.";
}

void Invigilator::HandleVaultJoinConfirmationAck(const std::string& message,
                                    std::function<void(bool)> callback) {  // NOLINT (Philip)
  MessageType type;
  std::string payload;
  if (!detail::UnwrapMessage(message, type, payload)) {
    LOG(kError) << "Failed to handle incoming message.";
    return;
  }
  if (type != MessageType::kVaultJoinConfirmationAck) {
    LOG(kError) << "Incoming message is of incorrect type.";
    return;
  }
  protobuf::VaultJoinConfirmationAck ack;
  ack.ParseFromString(payload);
  callback(ack.ack());
}

#if defined MAIDSAFE_LINUX
bool Invigilator::IsInstaller(const fs::path& path) {
  return path.extension() == ".deb"
         && path.stem().string().length() > 8
         && path.stem().string().substr(0, 9) == "LifeStuff";
}
#else
bool Invigilator::IsInstaller(const fs::path& /*path*/) { return false; }
#endif

void Invigilator::UpdateExecutor() {
  std::vector<fs::path> updated_files;
  if (download_manager_.Update(updated_files) == kSuccess) {
//    WriteConfigFile();
#if defined MAIDSAFE_LINUX
    auto it(std::find_if(updated_files.begin(), updated_files.end(),
                         [&](const fs::path& path)->bool { return IsInstaller(path); }));  // NOLINT
    if (it != updated_files.end()) {
      LOG(kInfo) << "Found new installer at " << (*it).string();
      std::string command("dpkg -i " + (*it).string());
      system(command.c_str());
    } else {
      LOG(kError) << "Update failed: could not find installer in list of updated files";
    }
    //  FIND INSTALLER IN UPDATED FILES
    //  RUN DPKG ON INSTALLER
#elif defined MAIDSAFE_APPLE
    //  FIND INSTALLER IN UPDATED FILES
    //  RUN INSTALLER SOMEHOW
#else
    //  TELL CLIENT TO RUN INSTALLER AND RESTART INVIGILATOR
#endif
  }
}

bool Invigilator::InTestMode() const {
  return config_file_path_ == fs::path(".") / detail::kGlobalConfigFilename;
}

std::vector<Invigilator::VaultInfoPtr>::iterator Invigilator::FindFromIdentity(
    const std::string& identity) {
  return std::find_if(vault_infos_.begin(),
                      vault_infos_.end(),
                      [identity] (const VaultInfoPtr& vault_info)->bool {
                        return vault_info->keys.identity == identity;
                      });
}

std::vector<Invigilator::VaultInfoPtr>::iterator Invigilator::FindFromProcessIndex(
    ProcessIndex process_index) {
  return std::find_if(vault_infos_.begin(),
                      vault_infos_.end(),
                      [process_index] (const VaultInfoPtr& vault_info)->bool {
                        return vault_info->process_index == process_index;
                      });
}

void Invigilator::RestartVault(const std::string& identity) {
  std::lock_guard<std::mutex> lock(vault_infos_mutex_);
  auto itr(FindFromIdentity(identity));
  if (itr == vault_infos_.end()) {
    LOG(kError) << "Vault with identity " << Base64Substr(identity) << " hasn't been added.";
    return;
  }
  process_manager_.StartProcess((*itr)->process_index);
}

// NOTE: vault_infos_mutex_ must be locked before calling this function.
// TODO(Fraser#5#): 2012-08-17 - This is pretty heavy-handed - locking for duration of function.
//                               Try to reduce lock scope eventually.
bool Invigilator::StopVault(const std::string& identity,
                            const std::string& data,
                            const std::string& signature,
                            bool permanent) {
  auto itr(FindFromIdentity(identity));
  if (itr == vault_infos_.end()) {
    LOG(kError) << "Vault with identity " << Base64Substr(identity) << " hasn't been added.";
    return false;
  }
  (*itr)->requested_to_run = !permanent;
  process_manager_.LetProcessDie((*itr)->process_index);
  protobuf::VaultShutdownRequest vault_shutdown_request;
  vault_shutdown_request.set_process_index((*itr)->process_index);
  vault_shutdown_request.set_data(data);
  vault_shutdown_request.set_signature(signature);
  std::shared_ptr<LocalTcpTransport> sending_transport(
      new LocalTcpTransport(asio_service_.service()));
  int result(0);
  sending_transport->Connect((*itr)->vault_port, result);
  if (result != kSuccess) {
    LOG(kError) << "Failed to connect sending transport to vault.";
    return false;
  }

  sending_transport->Send(detail::WrapMessage(MessageType::kVaultShutdownRequest,
                                              vault_shutdown_request.SerializeAsString()),
                                              (*itr)->vault_port);
  LOG(kInfo) << "Sent shutdown request to vault on port " << (*itr)->vault_port;
  return process_manager_.WaitForProcessToStop((*itr)->process_index);
}

void Invigilator::StopAllVaults() {
  std::lock_guard<std::mutex> lock(vault_infos_mutex_);
  std::for_each(vault_infos_.begin(),
                vault_infos_.end(),
                [this] (const VaultInfoPtr& info) {
                  if (process_manager_.GetProcessStatus(info->process_index)
                          != ProcessStatus::kRunning)
                  return;
                  std::string random_data(RandomString(64)), signature;
                  if (asymm::Sign(random_data, info->keys.private_key, &signature) != kSuccess)
                    LOG(kError) << "StopAllVaults: failed to sign - "
                                << Base64Substr(info->keys.identity);
                  if (!StopVault(info->keys.identity, random_data, signature, false))
                    LOG(kError) << "StopAllVaults: failed to stop - "
                                << Base64Substr(info->keys.identity);
                });
}

/*
//  void Invigilator::EraseVault(const std::string& account_name) {
//    if (index < static_cast<int32_t>(processes_.size())) {
//      auto itr(processes_.begin() + (index - 1));
//      process_manager_.KillProcess((*itr).second);
//      processes_.erase(itr);
//      LOG(kInfo) << "Erasing vault...";
//      if (WriteConfig()) {
//        LOG(kInfo) << "Done!";
//      }
//    } else {
//      LOG(kError) << "Invalid index of " << index << " for processes container with size "
//                  << processes_.size();
//    }
//  }

//  int32_t Invigilator::ListVaults(bool select) const {
//    fs::path path((GetSystemAppDir() / "config.txt"));
//
//    std::string content;
//    ReadFile(path, &content);
//
//    typedef boost::tokenizer<boost::char_separator<char>> vault_tokenizer;
//    boost::char_separator<char> delimiter("\n", "", boost::keep_empty_tokens);
//    vault_tokenizer tok(content, delimiter);
//
//    int32_t i = 1;
//    LOG(kInfo) << "************************************************************";
//    for (vault_tokenizer::iterator iterator = tok.begin(); iterator != tok.end(); ++iterator) {
//      LOG(kInfo) << i << ". " << *iterator;
//      i++;
//    }
//    LOG(kInfo) << "************************************************************";
//
//    if (select) {
//      int32_t option;
//      LOG(kInfo) << "Select an item: ";
//      std::cin >> option;
//      return option;
//    }
//
//    return 0;
//  }
*/

bool Invigilator::ObtainBootstrapInformation(protobuf::InvigilatorConfig& config) {
  std::string serialised_endpoints(download_manager_.RetrieveBootstrapInfo());
  if (serialised_endpoints.empty()) {
    LOG(kError) << "Retrieved endpoints are empty.";
    return false;
  }

  protobuf::BootstrapEndpoints bootstrap_endpoints;
  if (!bootstrap_endpoints.ParseFromString(serialised_endpoints)) {
    LOG(kError) << "Retrieved endpoints do not parse.";
    return false;
  }

  config.mutable_bootstrap_endpoints()->CopyFrom(bootstrap_endpoints);

  return true;
}

bool Invigilator::StartVaultProcess(VaultInfoPtr& vault_info) {
  Process process;
#ifdef USE_TEST_KEYS
  std::string process_name(detail::kDummyName);
  fs::path executable_path(".");
# ifdef MAIDSAFE_WIN32
    TCHAR file_name[MAX_PATH];
    if (GetModuleFileName(NULL, file_name, MAX_PATH))
      executable_path = fs::path(file_name).parent_path();
# endif
#else
  std::string process_name(detail::kVaultName);
  fs::path executable_path(GetAppInstallDir());
#endif
  if (!process.SetExecutablePath(executable_path /
                                 (process_name + detail::kThisPlatform().executable_extension()))) {
    LOG(kError) << "Failed to set executable path for: " << Base64Substr(vault_info->keys.identity);
    return false;
  }

  LOG(kInfo) << "Process Name: " << process.name();
  vault_info->process_index = process_manager_.AddProcess(process, local_port_);
  if (vault_info->process_index == ProcessManager::kInvalidIndex()) {
    LOG(kError) << "Error starting vault with ID: " << Base64Substr(vault_info->keys.identity);
    return false;
  }

  vault_infos_.push_back(vault_info);
  process_manager_.StartProcess(vault_info->process_index);
  return true;
}

bool ReadFileToInvigilatorConfig(const fs::path& file_path, protobuf::InvigilatorConfig& config) {
  std::string config_content;
  if (!ReadFile(file_path, &config_content) || config_content.empty()) {
    // TODO(Team): Should have counter for failures to trigger recreation?
    LOG(kError) << "Failed to read config file " << file_path;
    return false;
  }

  if (!config.ParseFromString(config_content)) {
    // TODO(Team): Should have counter for failures to trigger recreation?
    LOG(kError) << "Failed to read config file " << file_path;
    return false;
  }

  return true;
}

bool Invigilator::ReadBootstrapEndpoints(protobuf::InvigilatorConfig& config,
                                         std::vector<EndPoint >& endpoints) {
  if (!ReadFileToInvigilatorConfig(config_file_path_, config)) {
    // TODO(Team): Should have counter for failures to trigger recreation?
    LOG(kError) << "Failed to read & parse config file " << config_file_path_;
    return false;
  }

  protobuf::BootstrapEndpoints end_points(config.bootstrap_endpoints());
  int max_index(end_points.bootstrap_endpoint_ip_size() >
                end_points.bootstrap_endpoint_port_size() ?
                    end_points.bootstrap_endpoint_port_size() :
                    end_points.bootstrap_endpoint_ip_size());
  for (int n(0); n < max_index; ++n) {
    endpoints.push_back(std::make_pair(end_points.bootstrap_endpoint_ip(n),
                                       end_points.bootstrap_endpoint_port(n)));
  }

  return true;
}

bool Invigilator::AddBootstrapEndPoint(const std::string& ip, const uint16_t& port) {
  protobuf::InvigilatorConfig config;
  std::vector<EndPoint> endpoints;
  if (!ReadBootstrapEndpoints(config, endpoints)) {
    LOG(kError) << "Failed to get endpoints.";
    return false;
  }

  auto it(std::find_if(endpoints.begin(),
                       endpoints.end(),
                       [&ip, &port] (const EndPoint& element)->bool {
                         return element.first == ip && element.second == port;
                       }));

  if (it == endpoints.end()) {
    protobuf::BootstrapEndpoints *eps = config.mutable_bootstrap_endpoints();
    eps->add_bootstrap_endpoint_ip(ip);
    eps->add_bootstrap_endpoint_port(port);
    if (!WriteFile(config_file_path_, config.SerializeAsString())) {
      LOG(kError) << "Failed to write config file after adding endpoint.";
      return false;
    }
  } else {
    LOG(kInfo) << "Endpoint " << ip << ":" << port << "already in config file.";
  }

  return true;
}

bool Invigilator::AmendVaultDetailsInConfigFile(const VaultInfoPtr& vault_info,
                                                bool existing_vault) {
  protobuf::InvigilatorConfig config;
  if (!ReadFileToInvigilatorConfig(config_file_path_, config)) {
    LOG(kError) << "Failed to read config file to amend details of vault ID "
                << Base64Substr(vault_info->keys.identity);
    return false;
  }

  if (existing_vault) {
    for (int n(0); n < config.vault_info_size(); ++n) {
      asymm::Keys keys;
      if (!asymm::ParseKeys(config.vault_info(n).keys(), keys))
        continue;
      if (vault_info->keys.identity == keys.identity) {
        std::string serialised_keys;
        if (!asymm::SerialiseKeys(vault_info->keys, serialised_keys)) {
          LOG(kError) << "Failed to serialise keys to amend details of vault ID "
                      << Base64Substr(vault_info->keys.identity);
          return false;
        }

        protobuf::VaultInfo* p_info = config.mutable_vault_info(n);
        p_info->set_account_name(vault_info->account_name);
        p_info->set_keys(serialised_keys);
        p_info->set_chunkstore_path(vault_info->chunkstore_path);
        p_info->set_requested_to_run(vault_info->requested_to_run);
        n = config.vault_info_size();
      }
    }
  } else {
    protobuf::VaultInfo* p_info = config.add_vault_info();
    p_info->set_account_name(vault_info->account_name);
    std::string serialised_keys;
    if (!asymm::SerialiseKeys(vault_info->keys, serialised_keys)) {
      LOG(kError) << "Failed to serialise keys to amend details of vault ID "
                  << Base64Substr(vault_info->keys.identity);
      return false;
    }
    p_info->set_keys(serialised_keys);
    p_info->set_chunkstore_path(vault_info->chunkstore_path);
    p_info->set_requested_to_run(true);
    if (!WriteFile(config_file_path_, config.SerializeAsString())) {
      LOG(kError) << "Failed to write config file to amend details of vault ID "
                  << Base64Substr(vault_info->keys.identity);
      return false;
    }
  }
  if (!WriteFile(config_file_path_, config.SerializeAsString())) {
    LOG(kError) << "Failed to write config file after adding endpoint.";
    return false;
  }

  return true;
}

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
