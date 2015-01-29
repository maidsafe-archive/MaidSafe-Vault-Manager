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
#include "maidsafe/common/serialisation/serialisation.h"
#include "maidsafe/common/tcp/connection.h"
#include "maidsafe/common/tcp/listener.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/nfs/client/maid_client.h"

#include "maidsafe/vault_manager/client_connections.h"
#include "maidsafe/vault_manager/new_connections.h"
#include "maidsafe/vault_manager/process_manager.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/messages/challenge.h"
#include "maidsafe/vault_manager/messages/challenge_response.h"
#include "maidsafe/vault_manager/messages/joined_network.h"
#include "maidsafe/vault_manager/messages/log_message.h"
#include "maidsafe/vault_manager/messages/max_disk_usage_update.h"
#include "maidsafe/vault_manager/messages/network_stable_request.h"
#include "maidsafe/vault_manager/messages/network_stable_response.h"
#include "maidsafe/vault_manager/messages/set_network_as_stable.h"
#include "maidsafe/vault_manager/messages/start_vault_request.h"
#include "maidsafe/vault_manager/messages/take_ownership_request.h"
#include "maidsafe/vault_manager/messages/validate_connection_request.h"
#include "maidsafe/vault_manager/messages/vault_running_response.h"
#include "maidsafe/vault_manager/messages/vault_shutdown_request.h"
#include "maidsafe/vault_manager/messages/vault_started.h"
#include "maidsafe/vault_manager/messages/vault_started_response.h"

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

fs::path GetConfigFilePath() { return GetPath(kConfigFilename); }

fs::path GetVaultDir(const std::string& debug_id) { return GetPath(debug_id); }

fs::path GetVaultExecutablePath() {
#ifdef TESTING
  if (!GetPathToVault().empty())
    return GetPathToVault();
#endif
  return process::GetOtherExecutablePath(fs::path{"vault"});
}

void PutPmidAndSigner(const passport::PmidAndSigner& pmid_and_signer) {
  std::shared_ptr<nfs_client::MaidClient> client_nfs(
      nfs_client::MaidClient::MakeShared(passport::MaidAndSigner{passport::CreateMaidAndSigner()}));
  client_nfs->Put(passport::PublicPmid{pmid_and_signer.first}).get();
  client_nfs->Put(passport::PublicAnpmid{pmid_and_signer.second}).get();
  client_nfs->Stop();
}

}  // unnamed namespace

VaultManager::VaultManager()
    : config_file_handler_(GetConfigFilePath()),
      network_stable_(false),
      tear_down_with_interval_(false),
      asio_service_(1),
      strand_(asio_service_.service()),
      listener_(tcp::Listener::MakeShared(
          strand_, [this](tcp::ConnectionPtr connection) { HandleNewConnection(connection); },
          GetInitialListeningPort())),
      process_manager_(ProcessManager::MakeShared(asio_service_.service(), GetVaultExecutablePath(),
                                                  listener_->ListeningPort())),
      client_connections_(ClientConnections::MakeShared(asio_service_.service())),
      new_connections_(NewConnections::MakeShared(asio_service_.service())) {
  std::vector<VaultInfo> vaults{config_file_handler_.ReadConfigFile()};
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
    vault_info.max_disk_usage = DiskUsage{(9 * space_info.available) / 10};
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
  tcp::MessageReceivedFunctor on_message{
      [=](tcp::Message message) { HandleReceivedMessage(connection, std::move(message)); }};
  connection->Start(on_message, [=] { HandleConnectionClosed(connection); });
}

void VaultManager::HandleConnectionClosed(tcp::ConnectionPtr connection) {
  if (process_manager_->HandleConnectionClosed(connection) ||
      client_connections_->Remove(connection)) {
    return;
  }
  new_connections_->Remove(connection);
}

void VaultManager::HandleReceivedMessage(tcp::ConnectionPtr connection, tcp::Message&& message) {
  try {
    InputVectorStream binary_input_stream(std::move(message));
    MessageTag tag(static_cast<MessageTag>(-1));
    Parse(binary_input_stream, tag);
    switch (tag) {
      case MessageTag::kValidateConnectionRequest:
        HandleValidateConnectionRequest(connection);
        break;
      case MessageTag::kChallengeResponse:
        HandleChallengeResponse(connection, Parse<ChallengeResponse>(binary_input_stream));
        break;
      case MessageTag::kStartVaultRequest:
        HandleStartVaultRequest(connection, Parse<StartVaultRequest>(binary_input_stream));
        break;
      case MessageTag::kTakeOwnershipRequest:
        HandleTakeOwnershipRequest(connection, Parse<TakeOwnershipRequest>(binary_input_stream));
        break;
      case MessageTag::kVaultStarted:
        HandleVaultStarted(connection, Parse<VaultStarted>(binary_input_stream));
        break;
      case MessageTag::kJoinedNetwork:
        HandleJoinedNetwork(connection);
        break;
#ifdef TESTING
      case MessageTag::kSetNetworkAsStable:
        HandleSetNetworkAsStable();
        break;
      case MessageTag::kNetworkStableRequest:
        HandleNetworkStableRequest(connection);
        break;
#endif
      case MessageTag::kLogMessage:
        HandleLogMessage(connection, Parse<LogMessage>(binary_input_stream));
        break;
      default:
        return;
    }
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to handle incoming message: " << boost::diagnostic_information(e);
  }
}

void VaultManager::HandleValidateConnectionRequest(tcp::ConnectionPtr connection) {
  RemoveFromNewConnections(connection);
  asymm::PlainText plain_text{RandomString((RandomUint32() % 100) + 100)};

  client_connections_->Add(connection, plain_text);
  Send(connection, Challenge(std::move(plain_text)));
}

void VaultManager::HandleChallengeResponse(tcp::ConnectionPtr connection,
                                           ChallengeResponse&& challenge_response) {
  client_connections_->Validate(connection, *challenge_response.public_maid,
                                challenge_response.signature);
}


void VaultManager::HandleStartVaultRequest(tcp::ConnectionPtr connection,
                                           StartVaultRequest&& start_vault_request) {
  maidsafe_error error{MakeError(CommonErrors::unknown)};
  VaultInfo vault_info;
  try {
    passport::PublicMaid::Name client_name{client_connections_->FindValidated(connection)};
    vault_info.label = std::move(start_vault_request.vault_label);
    vault_info.max_disk_usage = start_vault_request.max_disk_usage;
    vault_info.owner_name = client_name;
#ifdef TESTING
    if (start_vault_request.pmid_list_index) {
      vault_info.pmid_and_signer = std::make_shared<passport::PmidAndSigner>(
          GetPmidAndSigner(*start_vault_request.pmid_list_index));
    }
#endif
    if (!vault_info.pmid_and_signer) {
      vault_info.pmid_and_signer =
          std::make_shared<passport::PmidAndSigner>(passport::CreatePmidAndSigner());
      PutPmidAndSigner(*vault_info.pmid_and_signer);
    }
    if (start_vault_request.vault_dir.empty()) {
      vault_info.vault_dir = GetVaultDir(DebugId(vault_info.pmid_and_signer->first.name().value));
      if (!fs::exists(vault_info.vault_dir))
        fs::create_directories(vault_info.vault_dir);
    } else {
      vault_info.vault_dir = std::move(start_vault_request.vault_dir);
    }
#ifdef USE_VLOGGING
    vault_info.vlog_session_id = std::move(start_vault_request.vlog_session_id);
#ifdef TESTING
    vault_info.send_hostname_to_visualiser_server =
        start_vault_request.send_hostname_to_visualiser_server;
#endif
#endif
    process_manager_->AddProcess(std::move(vault_info));
    config_file_handler_.WriteConfigFile(process_manager_->GetAll());
    return;
  } catch (const maidsafe_error& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
    error = e;
  } catch (const std::exception& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
  }
  LOG(kError) << "VaultManager::HandleStartVaultRequest reporting error";
  Send(connection, VaultRunningResponse(std::move(vault_info.label), std::move(error)));
}

void VaultManager::HandleTakeOwnershipRequest(tcp::ConnectionPtr connection,
                                              TakeOwnershipRequest&& take_ownership_request) {
  maidsafe_error error{MakeError(CommonErrors::unknown)};
  VaultInfo vault_info;
  try {
    passport::PublicMaid::Name client_name{client_connections_->FindValidated(connection)};

    NonEmptyString label{take_ownership_request.vault_label};
    fs::path new_vault_dir{take_ownership_request.vault_dir};
    DiskUsage new_max_disk_usage{take_ownership_request.max_disk_usage};
    VaultInfo vault_info{process_manager_->Find(label)};

    if (vault_info.vault_dir != new_vault_dir) {
      vault_info.vault_dir = new_vault_dir;
      vault_info.max_disk_usage = new_max_disk_usage;
      vault_info.owner_name = client_name;
      return ChangeChunkstorePath(std::move(vault_info));
    }

    if (vault_info.max_disk_usage != new_max_disk_usage && new_max_disk_usage != 0U)
      Send(vault_info.tcp_connection, MaxDiskUsageUpdate(new_max_disk_usage));

    process_manager_->AssignOwner(label, client_name, new_max_disk_usage);
    config_file_handler_.WriteConfigFile(process_manager_->GetAll());
    Send(connection,
         VaultRunningResponse(std::move(label), std::move(*vault_info.pmid_and_signer)));
    return;
  } catch (const maidsafe_error& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
    error = e;
  } catch (const std::exception& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
  }
  Send(connection, VaultRunningResponse(std::move(vault_info.label), std::move(error)));
}

void VaultManager::ChangeChunkstorePath(VaultInfo vault_info) {
  // TODO(Fraser#5#): 2014-05-13 - Handle sending a "MoveChunkstoreRequest" to avoid stopping then
  //                               restarting the vault.
  Send(vault_info.tcp_connection, VaultShutdownRequest());
  ProcessManager::OnExitFunctor on_exit{
      [this, vault_info](maidsafe_error /*error*/, int /*exit_code*/) {
        process_manager_->AddProcess(std::move(vault_info));
        config_file_handler_.WriteConfigFile(process_manager_->GetAll());
      }};
  process_manager_->StopProcess(vault_info.tcp_connection, on_exit);
}

void VaultManager::HandleVaultStarted(tcp::ConnectionPtr connection, VaultStarted&& vault_started) {
  // TODO(Fraser#5#): 2014-05-20 - We should validate received ProcessID since a malicious process
  //                  could have spotted a new vault process starting and jumped in with this TCP
  //                  connection before the new vault can connect, passing itself off as the new
  //                  vault (i.e. lying about its own Process ID).
  RemoveFromNewConnections(connection);
  VaultInfo vault_info{
      process_manager_->HandleVaultStarted(connection, {vault_started.process_id})};

  // Send vault its credentials
  Send(vault_info.tcp_connection, VaultStartedResponse(vault_info, config_file_handler_.SymmKey(),
                                                       config_file_handler_.SymmIv()));

  // If the corresponding client is connected, send it the credentials too
  if (vault_info.owner_name->IsInitialised()) {
    try {
      tcp::ConnectionPtr client{client_connections_->FindValidated(vault_info.owner_name)};
      Send(client, VaultRunningResponse(vault_info.label, *vault_info.pmid_and_signer));
    } catch (const std::exception&) {
    }  // We don't care if the client isn't connected.
  }

  LOG(kSuccess) << "Vault started.  Pmid ID: "
                << DebugId(vault_info.pmid_and_signer->first.name().value)
                << "  Process ID: " << vault_started.process_id
                << "  Label: " << vault_info.label.string();
}

#ifdef TESTING
void VaultManager::HandleSetNetworkAsStable() {
  asio_service_.service().dispatch([=] {
    std::vector<tcp::ConnectionPtr> all_clients{client_connections_->GetAll()};
    for (const auto& client : all_clients)
      Send(client, NetworkStableResponse());
    network_stable_ = true;
  });
}

void VaultManager::HandleNetworkStableRequest(tcp::ConnectionPtr connection) {
  asio_service_.service().dispatch([=] {
    // If network is already stable send reply, else do nothing since all clients get notified once
    // stable anyway.
    if (network_stable_)
      Send(connection, NetworkStableResponse());
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
    tcp::ConnectionPtr client{client_connections_->FindValidated(vault_info.owner_name)};
    Send(client, LogMessage(log_message));
  } catch (const std::exception&) {
  }  // We don't care if the client isn't connected.
}

void VaultManager::HandleLogMessage(tcp::ConnectionPtr connection, LogMessage&& log_message) {
  LOG(kInfo) << log_message.data;
  try {
    VaultInfo vault_info(process_manager_->Find(connection));
    tcp::ConnectionPtr client{client_connections_->FindValidated(vault_info.owner_name)};
    Send(client, std::move(log_message));
  } catch (const std::exception&) {
  }  // We don't care if the client isn't connected.
}

void VaultManager::RemoveFromNewConnections(tcp::ConnectionPtr connection) {
  if (!new_connections_->Remove(connection)) {
    LOG(kWarning) << "Connection not found in new_connections_.";
    BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::connection_not_found));
  }
}

}  // namespace vault_manager

}  // namespace maidsafe
