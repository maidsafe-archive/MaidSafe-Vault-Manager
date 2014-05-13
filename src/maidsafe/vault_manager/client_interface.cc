/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/vault_manager/client_interface.h"

#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/utils.h"


#include "maidsafe/vault_manager/tcp_connection.h"
#include "maidsafe/vault_manager/utils.h"


//#include <chrono>
//#include <limits>
//
//#include "boost/filesystem/operations.hpp"
//
//#include "maidsafe/common/config.h"
//#include "maidsafe/common/error.h"
//#include "maidsafe/common/log.h"
//
//#include "maidsafe/passport/passport.h"
//
//#include "maidsafe/vault_manager/controller_messages.pb.h"
//#include "maidsafe/vault_manager/vault_manager.h"
//#include "maidsafe/vault_manager/local_tcp_transport.h"
//#include "maidsafe/vault_manager/return_codes.h"
//#include "maidsafe/vault_manager/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

ClientInterface::ClientInterface(const passport::Maid& maid, AsioService& asio_service)
    : maid_(maid),
      asio_service_(asio_service),
      tcp_connection_(maidsafe::make_unique<TcpConnection>(asio_service,
                                                           [this](std::string message) {
                                                             HandleReceivedMessage(message);
                                                           },
                                                           [this]() {
                                                              // FIXME
                                                           },
                                                           kLivePort)) {}


void ClientInterface::HandleReceivedMessage(const std::string& wrapped_message) {
  try {
    MessageAndType message_and_type{ UnwrapMessage(wrapped_message) };
    LOG(kVerbose) << "Received " << message_and_type.second;
    switch (message_and_type.second) {
      case MessageType::kTakeOwnershipResponse:
//        HandleTakeOwnershipResponse(message_and_type.first);
        break;
      default:
        return;
    }
  }
  catch (const std::exception& e) {
    LOG(kError) << "Failed to handle incoming message: " << boost::diagnostic_information(e);
  }
}





//ClientInterface::ClientInterface(
//    std::function<void(const std::string&)> on_new_version_available_slot)
//#ifdef TESTING
//    : vault_manager_port_(detail::GetTestVaultManagerPort() == 0
//                                  ? VaultManager::kDefaultPort() + 100
//                                  : detail::GetTestVaultManagerPort()),
//#else
//      : vault_manager_port_(VaultManager::kDefaultPort()),
//#endif
//        local_port_(0),
//        on_new_version_available_(),
//        bootstrap_nodes_(),
//        joining_vaults_(),
//        joining_vaults_mutex_(),
//        joining_vaults_conditional_(),
//        asio_service_(3),
//        receiving_transport_(std::make_shared<LocalTcpTransport>(asio_service_.service())) {
//  OnMessageReceived::slot_type on_message_slot([this](
//      const std::string & message,
//      Port vault_manager_port) { HandleReceivedRequest(message, vault_manager_port); });
//  detail::StartControllerListeningPort(receiving_transport_, on_message_slot, local_port_);
//  std::string path_to_new_installer;
//  if (!ConnectToVaultManager(path_to_new_installer)) {
//    receiving_transport_->StopListening();
//    LOG(kError) << "ClientInterface::ClientInterface can't connect to VaultManager";
//    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::uninitialised));
//  }
//
//  on_new_version_available_.connect(on_new_version_available_slot);
//  if (!path_to_new_installer.empty())
//    on_new_version_available_(path_to_new_installer);
//}
//
//ClientInterface::~ClientInterface() { receiving_transport_->StopListening(); }




//
//#ifdef TESTING
//void ClientInterface::SetTestEnvironmentVariables(
//    Port test_vault_manager_port, fs::path test_env_root_dir, fs::path path_to_vault,
//    std::vector<boost::asio::ip::udp::endpoint> bootstrap_ips) {
//  detail::SetTestEnvironmentVariables(test_vault_manager_port, test_env_root_dir, path_to_vault,
//                                      bootstrap_ips);
//}
//#endif
//
//std::vector<boost::asio::ip::udp::endpoint> ClientInterface::BootstrapEndpoints() {
//  return bootstrap_nodes_;
//}
//
//bool ClientInterface::FindNextAcceptingPort(TransportPtr request_transport) {
//  int result(1);
//  Port manager_port(vault_manager_port_);
//  request_transport->Connect(manager_port, result);
//  while (result != kSuccess) {
//    ++manager_port;
//    if (manager_port > vault_manager_port_ + VaultManager::kMaxRangeAboveDefaultPort()) {
//      LOG(kError) << "ClientInterface failed to connect to VaultManager on all ports in range "
//                  << vault_manager_port_ << " to "
//                  << vault_manager_port_ + VaultManager::kMaxRangeAboveDefaultPort();
//      return false;
//    }
//    request_transport->Connect(manager_port, result);
//  }
//  vault_manager_port_ = manager_port;
//  return true;
//}
//
//bool ClientInterface::ConnectToVaultManager(std::string& path_to_new_installer) {
//  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
//  std::mutex mutex;
//  std::condition_variable condition_variable;
//  State state(kInitialising);
//
//  request_transport->on_message_received()
//      .connect([&mutex, &condition_variable, &state, &path_to_new_installer, this](
//           const std::string & message, Port vault_manager_port) {
//         HandleRegisterResponse(message, vault_manager_port, mutex, condition_variable, state,
//                                path_to_new_installer);
//       });
//  request_transport->on_error().connect([&mutex, &condition_variable, &state](const int & error) {
//    {
//      std::lock_guard<std::mutex> lock(mutex);
//      state = kFailed;
//    }
//    condition_variable.notify_one();
//    LOG(kError) << "Transport reported error code " << error;
//  });
//  while (FindNextAcceptingPort(request_transport)) {
//    protobuf::ClientRegistrationRequest request;
//    request.set_listening_port(local_port_);
//    request.set_version(VersionToInt(kApplicationVersion()));
//    request_transport->Send(
//        detail::WrapMessage(MessageType::kClientRegistrationRequest, request.SerializeAsString()),
//        vault_manager_port_);
//    LOG(kVerbose) << "Sending registration request to port " << vault_manager_port_;
//    {
//      std::unique_lock<std::mutex> lock(mutex);
//      if (!condition_variable.wait_for(lock, std::chrono::seconds(3),
//                                       [&state] { return state != kInitialising; })) {
//        LOG(kError) << "Timed out waiting for ClientInterface initialisation.";
//      } else {
//        break;
//      }
//    }
//  }
//
//  if (state != kVerified) {
//    LOG(kError) << "ClientInterface is uninitialised.";
//    return false;
//  }
//
//  return true;
//}
//
//void ClientInterface::HandleRegisterResponse(const std::string& message,
//                                              Port /*vault_manager_port*/, std::mutex& mutex,
//                                              std::condition_variable& condition_variable,
//                                              State& state, std::string& path_to_new_installer) {
//  MessageType type;
//  std::string payload;
//  if (!detail::UnwrapMessage(message, type, payload)) {
//    LOG(kError) << "Failed to handle incoming message.";
//    {
//      std::lock_guard<std::mutex> lock(mutex);
//      state = kFailed;
//    }
//    return condition_variable.notify_one();
//  }
//  protobuf::ClientRegistrationResponse response;
//  if (!response.ParseFromString(payload)) {
//    LOG(kError) << "Failed to parse ClientRegistrationResponse.";
//    {
//      std::lock_guard<std::mutex> lock(mutex);
//      state = kFailed;
//    }
//    return condition_variable.notify_one();
//  }
//
//  //  if (response.bootstrap_endpoint_ip_size() == 0 ||
//  //      response.bootstrap_endpoint_port_size() == 0) {
//  //    LOG(kError) << "Response has no bootstrap nodes.";
//  //    {
//  //      std::lock_guard<std::mutex> lock(mutex);
//  //      state = kFailed;
//  //    }
//  //    return condition_variable.notify_one();
//  //  }
//
//  if (response.has_path_to_new_installer()) {
//    boost::system::error_code error_code;
//    fs::path new_version(response.path_to_new_installer());
//    if (!fs::exists(new_version, error_code) || error_code) {
//      LOG(kError) << "New version file missing: " << new_version;
//    } else {
//      path_to_new_installer = new_version.string();
//    }
//  }
//
//  int max_index(response.bootstrap_endpoint_ip_size() > response.bootstrap_endpoint_port_size()
//                    ? response.bootstrap_endpoint_port_size()
//                    : response.bootstrap_endpoint_ip_size());
//  for (int n(0); n < max_index; ++n) {
//    try {
//      boost::asio::ip::udp::endpoint endpoint;
//      endpoint.address(boost::asio::ip::address::from_string(response.bootstrap_endpoint_ip(n)));
//      endpoint.port(
//          static_cast<unsigned short>(response.bootstrap_endpoint_port(n)));
//      bootstrap_nodes_.push_back(endpoint);
//    }
//    catch (...) {
//      continue;
//    }
//  }
//
//  LOG(kSuccess) << "Successfully registered with VaultManager on port "
//                << vault_manager_port_;
//  {
//    std::lock_guard<std::mutex> lock(mutex);
//    state = kVerified;
//  }
//  condition_variable.notify_one();
//}
//
//bool ClientInterface::StartVault(const passport::Pmid& pmid,
//                                  const passport::Maid::Name& account_name,
//                                  const fs::path& chunkstore) {
//  std::mutex local_mutex;
//  std::condition_variable local_cond_var;
//  bool done(false), local_result(false);
//  protobuf::StartVaultRequest start_vault_request;
//  start_vault_request.set_account_name(account_name->string());
//  start_vault_request.set_pmid(passport::SerialisePmid(pmid).string());
//  asymm::PlainText token(RandomString(16));
//  start_vault_request.set_token(token.string());
//  start_vault_request.set_token_signature(asymm::Sign(token, pmid.private_key()).string());
//  start_vault_request.set_credential_change(false);
//  start_vault_request.set_client_port(local_port_);
//  if (!chunkstore.empty())
//    start_vault_request.set_chunkstore_path(chunkstore.string());
//#ifdef TESTING
//  start_vault_request.set_identity_index(detail::IdentityIndex());
//#endif
//  std::function<void(bool)> callback =
//      [&](bool result) {
//    {
//      std::lock_guard<std::mutex> lock(local_mutex);
//      local_result = result;
//      done = true;
//    }
//    local_cond_var.notify_one();
//  };
//
//  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
//  int result(0);
//  request_transport->Connect(vault_manager_port_, result);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to connect request transport to VaultManager.";
//    return false;
//  }
//  request_transport->on_message_received().connect([this, callback](
//      const std::string & message, Port /*vault_manager_port*/) {
//    HandleStartStopVaultResponse<protobuf::StartVaultResponse>(message, callback);
//  });
//  request_transport->on_error().connect([this, callback](const int & error) {
//    LOG(kError) << "Transport reported error code " << error;
//    callback(false);
//  });
//
//  LOG(kVerbose) << "Sending request to start vault to port " << vault_manager_port_;
//  request_transport->Send(
//      detail::WrapMessage(MessageType::kStartVaultRequest, start_vault_request.SerializeAsString()),
//      vault_manager_port_);
//  {
//    std::unique_lock<std::mutex> local_lock(local_mutex);
//    if (!local_cond_var.wait_for(local_lock, std::chrono::seconds(10), [&done] { return done; })) {
//      LOG(kError) << "Timed out waiting for reply.";
//      return false;
//    }
//    if (!local_result) {
//      LOG(kError) << "Failed starting vault.";
//      return false;
//    }
//  }
//
//  std::unique_lock<std::mutex> lock(joining_vaults_mutex_);
//  joining_vaults_[pmid.name()] = false;
//  if (!joining_vaults_conditional_.wait_for(lock, std::chrono::minutes(1),
//                                            [&] { return joining_vaults_[pmid.name()]; })) {
//    LOG(kError) << "Timed out waiting for vault join confirmation.";
//    return false;
//  }
//  joining_vaults_.erase(pmid.name());
//
//  return true;
//}
//
//bool ClientInterface::StopVault(const asymm::PlainText& data, const asymm::Signature& signature,
//                                 const Identity& identity) {
//  std::mutex local_mutex;
//  std::condition_variable local_cond_var;
//  bool done(false), local_result(false);
//  protobuf::StopVaultRequest stop_vault_request;
//  stop_vault_request.set_data(data.string());
//  stop_vault_request.set_signature(signature.string());
//  stop_vault_request.set_identity(identity.string());
//
//  std::function<void(bool)> callback =
//      [&](bool result) {
//    {
//      std::lock_guard<std::mutex> lock(local_mutex);
//      local_result = result;
//      done = true;
//    }
//    local_cond_var.notify_one();
//  };
//
//  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
//  int result(0);
//  request_transport->Connect(vault_manager_port_, result);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to connect request transport to VaultManager.";
//    return false;
//  }
//  request_transport->on_message_received().connect([this, callback](
//      const std::string & message, Port /*vault_manager_port*/) {
//    HandleStartStopVaultResponse<protobuf::StopVaultResponse>(message, callback);
//  });
//  request_transport->on_error().connect([this, callback](const int & error) {
//    LOG(kError) << "Transport reported error code " << error;
//    callback(false);
//  });
//
//  LOG(kVerbose) << "Sending request to stop vault to port " << vault_manager_port_;
//  request_transport->Send(
//      detail::WrapMessage(MessageType::kStopVaultRequest, stop_vault_request.SerializeAsString()),
//      vault_manager_port_);
//
//  std::unique_lock<std::mutex> lock(local_mutex);
//  if (!local_cond_var.wait_for(lock, std::chrono::seconds(10), [&] { return done; })) {
//    LOG(kError) << "Timed out waiting for reply.";
//    return false;
//  }
//  if (!local_result)
//    LOG(kError) << "Failed stopping vault.";
//  return local_result;
//}
//
//template <typename ResponseType>
//void ClientInterface::HandleStartStopVaultResponse(
//    const std::string& message, const std::function<void(bool)>& callback) {
//  MessageType type;
//  std::string payload;
//  if (!detail::UnwrapMessage(message, type, payload)) {
//    LOG(kError) << "Failed to handle incoming message.";
//    callback(false);
//    return;
//  }
//
//  ResponseType vault_response;
//  if (!vault_response.ParseFromString(payload)) {
//    LOG(kError) << "Failed to parse response.";
//    callback(false);
//    return;
//  }
//
//  callback(vault_response.result());
//}
//
//bool ClientInterface::GetBootstrapNodes(
//    std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints) {
//  std::mutex local_mutex;
//  std::condition_variable local_cond_var;
//  bool done(false), success(false);
//  protobuf::BootstrapRequest request;
//  uint32_t message_id(maidsafe::RandomUint32());
//  request.set_message_id(message_id);
//
//  VoidFunctionBoolParam callback = [&](bool result) {
//    {
//      std::lock_guard<std::mutex> lock(local_mutex);
//      done = true;
//      success = result;
//    }
//    local_cond_var.notify_one();
//  };
//
//  TransportPtr request_transport(new LocalTcpTransport(asio_service_.service()));
//  int result(0);
//  request_transport->Connect(vault_manager_port_, result);
//  if (result != kSuccess) {
//    LOG(kError) << "Failed to connect request transport to VaultManager.";
//    return false;
//  }
//  request_transport->on_message_received().connect([this, callback, &bootstrap_endpoints](
//      const std::string & message, Port /*vault_manager_port*/) {
//    HandleBootstrapResponse(message, bootstrap_endpoints, callback);
//  });
//  request_transport->on_error().connect([callback](const int & error) {
//    LOG(kError) << "Transport reported error code " << error;
//    callback(false);
//  });
//  std::unique_lock<std::mutex> lock(local_mutex);
//  LOG(kVerbose) << "Requesting bootstrap nodes from port " << vault_manager_port_;
//  request_transport->Send(
//      detail::WrapMessage(MessageType::kBootstrapRequest, request.SerializeAsString()),
//      vault_manager_port_);
//  if (!local_cond_var.wait_for(lock, std::chrono::seconds(3),
//                               [&] { return done; })) {
//    LOG(kError) << "Timed out waiting for reply.";
//    return false;
//  }
//  return success;
//}
//
//void ClientInterface::HandleBootstrapResponse(
//    const std::string& message, std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints,
//    VoidFunctionBoolParam callback) {
//  MessageType type;
//  std::string payload;
//  if (!detail::UnwrapMessage(message, type, payload)) {
//    LOG(kError) << "Failed to handle incoming message.";
//    callback(false);
//    return;
//  }
//
//  protobuf::BootstrapResponse bootstrap_response;
//  if (!bootstrap_response.ParseFromString(payload)) {
//    LOG(kError) << "Failed to parse BootstrapResponse.";
//    callback(false);
//    return;
//  }
//
//  if (bootstrap_response.bootstrap_endpoint_ip_size() !=
//      bootstrap_response.bootstrap_endpoint_port_size()) {
//    LOG(kWarning) << "Number of ports in endpoints does not equal number of addresses";
//  }
//  int size(std::min(bootstrap_response.bootstrap_endpoint_ip_size(),
//                    bootstrap_response.bootstrap_endpoint_port_size()));
//  for (int i(0); i < size; ++i) {
//    try {
//      boost::asio::ip::udp::endpoint endpoint;
//      endpoint.address(
//          boost::asio::ip::address::from_string(bootstrap_response.bootstrap_endpoint_ip(i)));
//      endpoint.port(static_cast<unsigned short>( 
//          bootstrap_response.bootstrap_endpoint_port(i)));
//      bootstrap_endpoints.push_back(endpoint);
//    }
//    catch (...) {
//      continue;
//    }
//  }
//  bootstrap_nodes_ = bootstrap_endpoints;
//  callback(true);
//}
//
//void ClientInterface::HandleUpdateIntervalResponse(
//    const std::string& message,
//    const std::function<void(bptime::time_duration)>& callback) {
//  MessageType type;
//  std::string payload;
//  if (!detail::UnwrapMessage(message, type, payload)) {
//    LOG(kError) << "Failed to handle incoming message.";
//    callback(bptime::pos_infin);
//    return;
//  }
//
//  protobuf::UpdateIntervalResponse update_interval_response;
//  if (!update_interval_response.ParseFromString(payload) ||
//      !update_interval_response.IsInitialized()) {
//    LOG(kError) << "Failed to parse UpdateIntervalResponse.";
//    callback(bptime::pos_infin);
//    return;
//  }
//
//  if (update_interval_response.update_interval() == 0) {
//    LOG(kError) << "UpdateIntervalResponse indicates failure.";
//    callback(bptime::pos_infin);
//  } else {
//    callback(bptime::seconds(update_interval_response.update_interval()));
//  }
//}
//
//void ClientInterface::HandleReceivedRequest(const std::string& message, Port peer_port) {
//  /*assert(peer_port == vault_manager_port_);*/  // VaultManager does not currently use
//  // its established port to contact ClientInterface
//  MessageType type;
//  std::string payload;
//  if (!detail::UnwrapMessage(message, type, payload)) {
//    LOG(kError) << "Failed to handle incoming message.";
//    return;
//  }
//  LOG(kVerbose) << "HandleReceivedRequest: message type " << static_cast<int>(type) << " received.";
//  std::string response;
//  switch (type) {
//    case MessageType::kNewVersionAvailable:
//      HandleNewVersionAvailable(payload, response);
//      break;
//    case MessageType::kVaultJoinConfirmation:
//      HandleVaultJoinConfirmation(payload, response);
//      break;
//    default:
//      return;
//  }
//  receiving_transport_->Send(response, peer_port);
//}
//
//void ClientInterface::HandleNewVersionAvailable(const std::string& request,
//                                                 std::string& response) {
//  protobuf::NewVersionAvailable new_version_available;
//  protobuf::NewVersionAvailableAck new_version_available_ack;
//  if (!new_version_available.ParseFromString(request)) {
//    LOG(kError) << "Failed to parse NewVersionAvailable.";
//    new_version_available_ack.set_new_version_filepath("");
//  } else {
//    boost::system::error_code error_code;
//    fs::path new_version(new_version_available.new_version_filepath());
//    if (!fs::exists(new_version, error_code) || error_code) {
//      LOG(kError) << "New version file missing: " << new_version;
//      new_version_available_ack.set_new_version_filepath("");
//    } else {
//      new_version_available_ack.set_new_version_filepath(
//          new_version_available.new_version_filepath());
//    }
//  }
//  response = detail::WrapMessage(MessageType::kNewVersionAvailableAck,
//                                 new_version_available_ack.SerializeAsString());
//  on_new_version_available_(new_version_available.new_version_filepath());
//}
//
//void ClientInterface::HandleVaultJoinConfirmation(const std::string& request,
//                                                   std::string& response) {
//  protobuf::VaultJoinConfirmation vault_join_confirmation;
//  protobuf::VaultJoinConfirmationAck vault_join_confirmation_ack;
//  if (!vault_join_confirmation.ParseFromString(request)) {
//    LOG(kError) << "Failed to parse VaultJoinConfirmation.";
//    vault_join_confirmation_ack.set_ack(false);
//  } else {
//    passport::Pmid::Name identity(Identity(vault_join_confirmation.identity()));
//    std::lock_guard<std::mutex> lock(joining_vaults_mutex_);
//    if (joining_vaults_.find(identity) == joining_vaults_.end()) {
//      LOG(kError) << "Identity is not in list of joining vaults.";
//      vault_join_confirmation_ack.set_ack(false);
//    } else {
//      joining_vaults_[identity] = true;
//      joining_vaults_conditional_.notify_all();
//      vault_join_confirmation_ack.set_ack(true);
//    }
//  }
//  response = detail::WrapMessage(MessageType::kVaultJoinConfirmationAck,
//                                 vault_join_confirmation_ack.SerializeAsString());
//}

}  // namespace vault_manager

}  // namespace maidsafe
