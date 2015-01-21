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

#include "maidsafe/vault_manager/vault_manager.h"

#include <string>
#include <vector>

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/application_support_directories.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/process.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/tcp/connection.h"
#include "maidsafe/common/tcp/listener.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/nfs/client/maid_client.h"

#include "maidsafe/vault_manager/client_connections.h"
#include "maidsafe/vault_manager/dispatcher.h"
#include "maidsafe/vault_manager/interprocess_messages.pb.h"
#include "maidsafe/vault_manager/new_connections.h"
#include "maidsafe/vault_manager/process_manager.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace {

fs::path GetPath(const fs::path& p) {
#ifdef TESTING
  return (GetTestEnvironmentRootDir().empty() ? GetUserAppDir() : GetTestEnvironmentRootDir()) / p;
#else
  return GetSystemAppSupportDir() / p;
#endif
}

fs::path GetConfigFilePath() {
  return GetPath(kConfigFilename);
}

fs::path GetVaultDir(const std::string& debug_id) {
  return GetPath(debug_id);
}

fs::path GetVaultExecutablePath() {
#ifdef TESTING
  if (!GetPathToVault().empty())
    return GetPathToVault();
#endif
  return process::GetOtherExecutablePath(fs::path{ "vault" });
}

void PutPmidAndSigner(const passport::PmidAndSigner& pmid_and_signer) {
  LOG(kVerbose) << "Creating Random client to store public pmid key";
  std::shared_ptr<nfs_client::MaidClient> client_nfs(nfs_client::MaidClient::MakeShared(
      passport::MaidAndSigner{ passport::CreateMaidAndSigner() }));
  client_nfs->Put(passport::PublicPmid{ pmid_and_signer.first }).get();
  client_nfs->Put(passport::PublicAnpmid{ pmid_and_signer.second }).get();
  LOG(kVerbose) << "stored public pmid key";
  client_nfs->Stop();
  LOG(kVerbose) << "Stopped Nfs client";
}

}  // unnamed namespace

VaultManager::VaultManager()
    : config_file_handler_(GetConfigFilePath()),
      network_stable_(false),
      tear_down_with_interval_(false),
      asio_service_(1),
      listener_(tcp::Listener::MakeShared(asio_service_,
          [this](tcp::ConnectionPtr connection) { HandleNewConnection(connection); },
          GetInitialListeningPort())),
      process_manager_(ProcessManager::MakeShared(asio_service_.service(),
                       GetVaultExecutablePath(), listener_->ListeningPort())),
      client_connections_(ClientConnections::MakeShared(asio_service_.service())),
      new_connections_(NewConnections::MakeShared(asio_service_.service())) {
  std::vector<VaultInfo> vaults{ config_file_handler_.ReadConfigFile() };
  if (vaults.empty()) {
#ifndef TESTING
    VaultInfo vault_info;
    vault_info.pmid_and_signer =
        std::make_shared<passport::PmidAndSigner>(passport::CreatePmidAndSigner());
    // Try infinitely to put PmidAndSigner for a new Vault
    bool stored_pmid_and_signer(false);
    do {
      try {
        PutPmidAndSigner(*vault_info.pmid_and_signer);
        stored_pmid_and_signer = true;
        LOG(kSuccess) << "Put PmidAndSigner Successfully";
      } catch (const std::exception& e) {
        LOG(kError) << " Failed to put PmidAndSigner : " << boost::diagnostic_information(e);
      }
    } while (!stored_pmid_and_signer);

    vault_info.vault_dir = GetVaultDir(DebugId(vault_info.pmid_and_signer->first.name().value));
    if (!fs::exists(vault_info.vault_dir))
      fs::create_directories(vault_info.vault_dir);
    auto space_info(fs::space(vault_info.vault_dir));
    vault_info.max_disk_usage = DiskUsage{ (9 * space_info.available) / 10 };
    vault_info.label = GenerateLabel();
    process_manager_->AddProcess(std::move(vault_info));
    LOG(kSuccess) << "Vault process handed over to process manager.";
    config_file_handler_.WriteConfigFile(process_manager_->GetAll());
#endif
  } else {
    for (auto& vault_info : vaults)
      process_manager_->AddProcess(std::move(vault_info));
  }
  LOG(kInfo) << "VaultManager started";
}

void VaultManager::TearDownWithInterval() {
  tear_down_with_interval_ = true;
  auto listener(listener_);
  auto new_connections(new_connections_);
  auto client_connections(client_connections_);
  auto process_manager(process_manager_);
  auto future(std::async(std::launch::async, [=] {
    listener->StopListening();
    new_connections->CloseAll();
    client_connections->CloseAll();
    process_manager->StopAllWithInterval();
  }));
  future.get();
  asio_service_.Stop();
}

VaultManager::~VaultManager() {
  if (!tear_down_with_interval_) {
    auto listener(listener_);
    auto new_connections(new_connections_);
    auto client_connections(client_connections_);
    auto process_manager(process_manager_);
    asio_service_.service().post([=] {
      listener->StopListening();
      new_connections->CloseAll();
      client_connections->CloseAll();
      process_manager->StopAll();
    });
    asio_service_.Stop();
  }
}

void VaultManager::HandleNewConnection(tcp::ConnectionPtr connection) {
  new_connections_->Add(connection);
  tcp::MessageReceivedFunctor on_message{ [=](const std::string& message) {
    HandleReceivedMessage(connection, message);
  } };
  connection->Start(on_message, [=] { HandleConnectionClosed(connection); });
}

void VaultManager::HandleConnectionClosed(tcp::ConnectionPtr connection) {
  if (process_manager_->HandleConnectionClosed(connection) ||
      client_connections_->Remove(connection)) {
    return;
  }
  new_connections_->Remove(connection);
}

void VaultManager::HandleReceivedMessage(tcp::ConnectionPtr connection,
                                         const std::string& wrapped_message) {
  try {
    MessageAndType message_and_type{ UnwrapMessage(wrapped_message) };
    LOG(kVerbose) << "Received " << message_and_type.second;
    switch (message_and_type.second) {
      case MessageType::kValidateConnectionRequest:
        assert(message_and_type.first.empty());
        HandleValidateConnectionRequest(connection);
        break;
      case MessageType::kChallengeResponse:
        HandleChallengeResponse(connection, message_and_type.first);
        break;
      case MessageType::kStartVaultRequest:
        HandleStartVaultRequest(connection, message_and_type.first);
        break;
      case MessageType::kTakeOwnershipRequest:
        HandleTakeOwnershipRequest(connection, message_and_type.first);
        break;
      case MessageType::kVaultStarted:
        HandleVaultStarted(connection, message_and_type.first);
        break;
      case MessageType::kJoinedNetwork:
        assert(message_and_type.first.empty());
        HandleJoinedNetwork(connection);
        break;
#ifdef TESTING
      case MessageType::kMarkNetworkAsStable:
        assert(message_and_type.first.empty());
        HandleMarkNetworkAsStable();
        break;
      case MessageType::kNetworkStableRequest:
        assert(message_and_type.first.empty());
        HandleNetworkStableRequest(connection);
        break;
#endif
      case MessageType::kLogMessage:
        HandleLogMessage(connection, message_and_type.first);
        break;
      default:
        return;
    }
  }
  catch (const std::exception& e) {
    LOG(kError) << "Failed to handle incoming message: " << boost::diagnostic_information(e);
  }
}

void VaultManager::HandleValidateConnectionRequest(tcp::ConnectionPtr connection) {
  RemoveFromNewConnections(connection);
  asymm::PlainText challenge{ RandomString((RandomUint32() % 100) + 100) };

  client_connections_->Add(connection, challenge);
  SendChallenge(connection, challenge);
}

void VaultManager::HandleChallengeResponse(tcp::ConnectionPtr connection,
                                           const std::string& message) {
  protobuf::ChallengeResponse challenge_response{
      ParseProto<protobuf::ChallengeResponse>(message) };
  passport::PublicMaid maid{
      passport::PublicMaid::Name{ Identity{ challenge_response.public_maid_name() } },
      passport::PublicMaid::serialised_type{ NonEmptyString{
          challenge_response.public_maid_value() } } };
  asymm::Signature signature{ challenge_response.signature() };
  client_connections_->Validate(connection, maid, signature);
}


void VaultManager::HandleStartVaultRequest(tcp::ConnectionPtr connection,
                                           const std::string& message) {
  LOG(kVerbose) << "VaultManager::HandleStartVaultRequest";
  maidsafe_error error{ MakeError(CommonErrors::unknown) };
  VaultInfo vault_info;
  try {
    passport::PublicMaid::Name client_name{ client_connections_->FindValidated(connection) };
    protobuf::StartVaultRequest start_vault_message{
        ParseProto<protobuf::StartVaultRequest>(message) };
    vault_info.label = NonEmptyString{ start_vault_message.label() };
    vault_info.max_disk_usage = DiskUsage{ start_vault_message.max_disk_usage() };
    vault_info.owner_name = client_name;
#ifdef TESTING
    if (start_vault_message.has_pmid_list_index()) {
      vault_info.pmid_and_signer = std::make_shared<passport::PmidAndSigner>(
          GetPmidAndSigner(start_vault_message.pmid_list_index()));
    }
#endif
    LOG(kVerbose) << "VaultManager::HandleStartVaultRequest PutPmidAndSigner";
    if (!vault_info.pmid_and_signer) {
      vault_info.pmid_and_signer =
          std::make_shared<passport::PmidAndSigner>(passport::CreatePmidAndSigner());
      PutPmidAndSigner(*vault_info.pmid_and_signer);
    }
    LOG(kVerbose) << "VaultManager::HandleStartVaultRequest vault_dir";
    if (!start_vault_message.has_vault_dir()) {
      vault_info.vault_dir = GetVaultDir(DebugId(vault_info.pmid_and_signer->first.name().value));
      if (!fs::exists(vault_info.vault_dir))
        fs::create_directories(vault_info.vault_dir);
    } else {
      vault_info.vault_dir = start_vault_message.vault_dir();
    }
#ifdef USE_VLOGGING
    if (start_vault_message.has_vlog_session_id())
      vault_info.vlog_session_id = start_vault_message.vlog_session_id();
# ifdef TESTING
    if (start_vault_message.has_send_hostname_to_visualiser_server()) {
      vault_info.send_hostname_to_visualiser_server =
          start_vault_message.send_hostname_to_visualiser_server();
    }
# endif
#endif
    LOG(kVerbose) << "VaultManager::HandleStartVaultRequest recording";
    process_manager_->AddProcess(std::move(vault_info));
    config_file_handler_.WriteConfigFile(process_manager_->GetAll());
    return;
  }
  catch (const maidsafe_error& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
    error = e;
  }
  catch (const std::exception& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
  }
  LOG(kError) << "VaultManager::HandleStartVaultRequest reporting error";
  SendVaultRunningResponse(connection, vault_info.label, nullptr, &error);
}

void VaultManager::HandleTakeOwnershipRequest(tcp::ConnectionPtr connection,
                                              const std::string& message) {
  maidsafe_error error{ MakeError(CommonErrors::unknown) };
  VaultInfo vault_info;
  try {
    passport::PublicMaid::Name client_name{ client_connections_->FindValidated(connection) };
    protobuf::TakeOwnershipRequest take_ownership_request{
        ParseProto<protobuf::TakeOwnershipRequest>(message) };
    NonEmptyString label{ take_ownership_request.label() };
    fs::path new_vault_dir{ take_ownership_request.vault_dir() };
    DiskUsage new_max_disk_usage{ take_ownership_request.max_disk_usage() };
    VaultInfo vault_info{ process_manager_->Find(label) };

    if (vault_info.vault_dir != new_vault_dir) {
      vault_info.vault_dir = new_vault_dir;
      vault_info.max_disk_usage = new_max_disk_usage;
      vault_info.owner_name = client_name;
      return ChangeChunkstorePath(std::move(vault_info));
    }

    if (vault_info.max_disk_usage != new_max_disk_usage && new_max_disk_usage != 0U)
      SendMaxDiskUsageUpdate(vault_info.tcp_connection, new_max_disk_usage);

    process_manager_->AssignOwner(label, client_name, new_max_disk_usage);
    config_file_handler_.WriteConfigFile(process_manager_->GetAll());
    SendVaultRunningResponse(connection, label, vault_info.pmid_and_signer.get());
    return;
  }
  catch (const maidsafe_error& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
    error = e;
  }
  catch (const std::exception& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
  }
  SendVaultRunningResponse(connection, vault_info.label, nullptr, &error);
}

void VaultManager::ChangeChunkstorePath(VaultInfo vault_info) {
  // TODO(Fraser#5#): 2014-05-13 - Handle sending a "MoveChunkstoreRequest" to avoid stopping then
  //                               restarting the vault.
  SendVaultShutdownRequest(vault_info.tcp_connection);
  ProcessManager::OnExitFunctor on_exit{ [this, vault_info](maidsafe_error error, int exit_code) {
    LOG(kVerbose) << "Process returned " << exit_code << " with error message: "
                  << boost::diagnostic_information(error);
    process_manager_->AddProcess(std::move(vault_info));
    config_file_handler_.WriteConfigFile(process_manager_->GetAll());
  } };
  process_manager_->StopProcess(vault_info.tcp_connection, on_exit);
}

void VaultManager::HandleVaultStarted(tcp::ConnectionPtr connection, const std::string& message) {
  // TODO(Fraser#5#): 2014-05-20 - We should validate received ProcessID since a malicious process
  //                  could have spotted a new vault process starting and jumped in with this TCP
  //                  connection before the new vault can connect, passing itself off as the new
  //                  vault (i.e. lying about its own Process ID).
  LOG(kVerbose) << "VaultManager::HandleVaultStarted";
  RemoveFromNewConnections(connection);
  protobuf::VaultStarted vault_started{ ParseProto<protobuf::VaultStarted>(message) };
  VaultInfo vault_info{
      process_manager_->HandleVaultStarted(connection, { vault_started.process_id() }) };

  // Send vault its credentials
  LOG(kVerbose) << "VaultManager::HandleVaultStarted Send vault its credentials";
  SendVaultStartedResponse(vault_info, config_file_handler_.SymmKey(),
                           config_file_handler_.SymmIv());

  // If the corresponding client is connected, send it the credentials too
  if (vault_info.owner_name->IsInitialised()) {
    try {
      LOG(kVerbose) << "VaultManager::HandleVaultStarted Send client its credentials";
      tcp::ConnectionPtr client{ client_connections_->FindValidated(vault_info.owner_name) };
      SendVaultRunningResponse(client, vault_info.label, vault_info.pmid_and_signer.get());
    }
    catch (const std::exception&) {}  // We don't care if the client isn't connected.
  }

  LOG(kSuccess) << "Vault started.  Pmid ID: "
      << DebugId(vault_info.pmid_and_signer->first.name().value) << "  Process ID: "
      << vault_started.process_id() << "  Label: " << vault_info.label.string();
}

#ifdef TESTING
void VaultManager::HandleMarkNetworkAsStable() {
  asio_service_.service().dispatch([=] {
    std::vector<tcp::ConnectionPtr> all_clients{ client_connections_->GetAll() };
    for (const auto& client : all_clients)
      SendNetworkStableResponse(client);
    network_stable_ = true;
  });
}

void VaultManager::HandleNetworkStableRequest(tcp::ConnectionPtr connection) {
  asio_service_.service().dispatch([=] {
    // If network is already stable send reply, else do nothing since all clients get notified once
    // stable anyway.
    if (network_stable_)
      SendNetworkStableResponse(connection);
  });
}
#endif

void VaultManager::HandleJoinedNetwork(tcp::ConnectionPtr connection) {
  try {
    VaultInfo vault_info(process_manager_->Find(connection));
    // TODO(Prakash) do vault_info need joined field
    std::string log_message("Vault running as " +
                            HexSubstr(vault_info.pmid_and_signer->first.name().value));
    LOG(kInfo) << log_message;
    tcp::ConnectionPtr client{ client_connections_->FindValidated(vault_info.owner_name) };
    SendLogMessage(client, log_message);
  }
  catch (const std::exception&) {}  // We don't care if the client isn't connected.
}

void VaultManager::HandleLogMessage(tcp::ConnectionPtr connection, const std::string& message) {
  LOG(kInfo) << message;
  try {
    VaultInfo vault_info(process_manager_->Find(connection));
    tcp::ConnectionPtr client{ client_connections_->FindValidated(vault_info.owner_name) };
    SendLogMessage(client, message);
  }
  catch (const std::exception&) {}  // We don't care if the client isn't connected.
}

void VaultManager::RemoveFromNewConnections(tcp::ConnectionPtr connection) {
  if (!new_connections_->Remove(connection)) {
    LOG(kWarning) << "Connection not found in new_connections_.";
    BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::connection_not_found));
  }
}

}  // namespace vault_manager

}  // namespace maidsafe
