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
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/process.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/routing/bootstrap_file_operations.h"

#include "maidsafe/vault_manager/dispatcher.h"
#include "maidsafe/vault_manager/interprocess_messages.pb.h"
#include "maidsafe/vault_manager/tcp_connection.h"
#include "maidsafe/vault_manager/tcp_listener.h"
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

fs::path GetBootstrapFilePath() {
  return GetPath(kBootstrapFilename);
}

fs::path GetDefaultVaultDir() {
  return GetPath(kVaultDirname);
}

fs::path GetVaultExecutablePath() {
#ifdef TESTING
  if (!GetPathToVault().empty())
    return GetPathToVault();
#endif
  return process::GetOtherExecutablePath(fs::path{ "vault" });
}

#ifdef TESTING
void SetPublicPmidList(const std::string& serialised_public_pmids,
                       std::mutex& mutex, std::vector<passport::PublicPmid>& public_pmids) {
  protobuf::PublicPmidList proto_public_pmids{
      ParseProto<protobuf::PublicPmidList>(serialised_public_pmids) };
  std::lock_guard<std::mutex> lock{ mutex };
  public_pmids.clear();
  public_pmids.reserve(proto_public_pmids.public_pmids_size());
  for (const auto& i : proto_public_pmids.public_pmids()) {
    passport::PublicPmid public_pmid(passport::PublicPmid::Name(Identity(i.public_pmid_name())),
        passport::PublicPmid::serialised_type(NonEmptyString(i.public_pmid())));
    public_pmids.push_back(public_pmid);
  }
}
#endif

}  // unnamed namespace

VaultManager::VaultManager()
    : kBootstrapFilePath_(GetBootstrapFilePath()),
      config_file_handler_(GetConfigFilePath()),
      listener_(maidsafe::make_unique<TcpListener>(
          [this](TcpConnectionPtr connection) { HandleNewConnection(connection); },
          GetInitialListeningPort())),
      new_connections_mutex_(),
      new_connections_(),
      asio_service_(maidsafe::make_unique<AsioService>(1)),
      process_manager_(asio_service_->service(), GetVaultExecutablePath(),
                       listener_->ListeningPort()),
      client_connections_(asio_service_->service()) {
  std::vector<VaultInfo> vaults{ config_file_handler_.ReadConfigFile() };
  if (vaults.empty()) {
    VaultInfo vault_info;
    vault_info.vault_dir = GetDefaultVaultDir();
    // TODO(Fraser#5#): 2014-05-19 - BEFORE_RELEASE handle size properly.
    vault_info.max_disk_usage = DiskUsage{ 10000000000 };
#ifdef TESTING
    // Use the 3rd Pmid from the zero-state Pmid list if available
    if (!GetPublicPmids().empty()) {
      vault_info.pmid_and_signer = std::make_shared<passport::PmidAndSigner>(GetPmidAndSigner(2));
      vault_info.label = NonEmptyString("first vault");
    } else {
      vault_info.label = GenerateLabel();
    }
#endif
    if (!vault_info.pmid_and_signer) {
      vault_info.pmid_and_signer =
          std::make_shared<passport::PmidAndSigner>(passport::CreatePmidAndSigner());
    }
    process_manager_.AddProcess(std::move(vault_info));
  } else {
    for (auto& vault_info : vaults)
      process_manager_.AddProcess(std::move(vault_info));
  }
  LOG(kInfo) << "VaultManager started";
}

VaultManager::~VaultManager() {
  std::vector<VaultInfo> all_vaults{ process_manager_.GetAll() };
  std::for_each(std::begin(all_vaults), std::end(all_vaults),
                [this](const VaultInfo& vault) {
                  // TODO(Fraser#5#): 2014-05-16 - Protect connection
                  if (vault.tcp_connection) {
                    SendVaultShutdownRequest(vault.tcp_connection);
                    process_manager_.StopProcess(vault.tcp_connection);
                  }
                });
  listener_.reset();
  asio_service_.reset();
}

void VaultManager::HandleNewConnection(TcpConnectionPtr connection) {
  {
    std::lock_guard<std::mutex> lock{ new_connections_mutex_ };
    TimerPtr timer{ std::make_shared<Timer>(asio_service_->service(), kRpcTimeout) };
    timer->async_wait([=](const boost::system::error_code& error_code) {
      if (error_code && error_code == boost::asio::error::operation_aborted) {
        LOG(kVerbose) << "New connection timer cancelled OK.";
      } else {
        LOG(kWarning) << "Timed out waiting for new connection to identify itself.";
        std::lock_guard<std::mutex> lock{ new_connections_mutex_ };
        new_connections_.erase(connection);
      }
    });
    bool result{ new_connections_.emplace(connection, timer).second };
    assert(result);
    static_cast<void>(result);
  }
  MessageReceivedFunctor on_message{ [=](const std::string& message) {
    HandleReceivedMessage(connection, message);
  } };
  connection->Start(on_message, [=] { HandleConnectionClosed(connection); });
}

void VaultManager::HandleConnectionClosed(TcpConnectionPtr connection) {
  // Need to lock for entire duration of this function to avoid moving a connection from
  // 'new_connections_' to 'process_manager_' or 'client_connections_' concurrently with the
  // connection closing.
  std::lock_guard<std::mutex> lock{ new_connections_mutex_ };
  if (process_manager_.HandleConnectionClosed(connection) || client_connections_.Remove(connection))
    return;
  new_connections_.erase(connection);
}

void VaultManager::HandleReceivedMessage(TcpConnectionPtr connection,
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

void VaultManager::HandleValidateConnectionRequest(TcpConnectionPtr connection) {
  RemoveFromNewConnections(connection);
  asymm::PlainText challenge{ RandomString((RandomUint32() % 100) + 100) };

  client_connections_.Add(connection, challenge);
  SendChallenge(connection, challenge);
}

void VaultManager::HandleChallengeResponse(TcpConnectionPtr connection,
                                           const std::string& message) {
  protobuf::ChallengeResponse challenge_response{
      ParseProto<protobuf::ChallengeResponse>(message) };
  passport::PublicMaid maid{
      passport::PublicMaid::Name{ Identity{ challenge_response.public_maid_name() } },
      passport::PublicMaid::serialised_type{ NonEmptyString{
          challenge_response.public_maid_value() } } };
  asymm::Signature signature{ challenge_response.signature() };
  client_connections_.Validate(connection, maid, signature);
}


void VaultManager::HandleStartVaultRequest(TcpConnectionPtr connection,
                                           const std::string& message) {
  maidsafe_error error{ MakeError(CommonErrors::unknown) };
  VaultInfo vault_info;
  try {
    passport::PublicMaid::Name client_name{ client_connections_.FindValidated(connection) };
    protobuf::StartVaultRequest start_vault_message{
        ParseProto<protobuf::StartVaultRequest>(message) };
    vault_info.label = NonEmptyString{ start_vault_message.label() };
    vault_info.vault_dir = start_vault_message.vault_dir();
    vault_info.max_disk_usage = DiskUsage{ start_vault_message.max_disk_usage() };
    vault_info.owner_name = client_name;
    process_manager_.AddProcess(std::move(vault_info));
    config_file_handler_.WriteConfigFile(process_manager_.GetAll());
#ifdef TESTING
    if (start_vault_message.has_pmid_list_index()) {
      vault_info.pmid_and_signer = std::make_shared<passport::PmidAndSigner>(
          GetPmidAndSigner(start_vault_message.pmid_list_index()));
    }
#endif
    return;
  }
  catch (const maidsafe_error& e) {
    LOG(kWarning) << e.what();
    error = e;
  }
  catch (const std::exception& e) {
    LOG(kWarning) << e.what();
  }
  SendVaultRunningResponse(connection, vault_info.label, nullptr, &error);
}

void VaultManager::HandleTakeOwnershipRequest(TcpConnectionPtr connection,
                                              const std::string& message) {
  maidsafe_error error{ MakeError(CommonErrors::unknown) };
  VaultInfo vault_info;
  try {
    passport::PublicMaid::Name client_name{ client_connections_.FindValidated(connection) };
    protobuf::TakeOwnershipRequest take_ownership_request{
        ParseProto<protobuf::TakeOwnershipRequest>(message) };
    NonEmptyString label{ take_ownership_request.label() };
    fs::path new_vault_dir{ take_ownership_request.vault_dir() };
    DiskUsage new_max_disk_usage{ take_ownership_request.max_disk_usage() };
    VaultInfo vault_info{ process_manager_.Find(label) };

    if (vault_info.vault_dir != new_vault_dir) {
      vault_info.vault_dir = new_vault_dir;
      vault_info.max_disk_usage = new_max_disk_usage;
      vault_info.owner_name = client_name;
      return ChangeChunkstorePath(std::move(vault_info));
    }

    if (vault_info.max_disk_usage != new_max_disk_usage && new_max_disk_usage != 0U)
      SendMaxDiskUsageUpdate(vault_info.tcp_connection, new_max_disk_usage);

    process_manager_.AssignOwner(label, client_name, new_max_disk_usage);
    config_file_handler_.WriteConfigFile(process_manager_.GetAll());
    SendVaultRunningResponse(connection, label, vault_info.pmid_and_signer.get());
    return;
  }
  catch (const maidsafe_error& e) {
    LOG(kWarning) << e.what();
    error = e;
  }
  catch (const std::exception& e) {
    LOG(kWarning) << e.what();
  }
  SendVaultRunningResponse(connection, vault_info.label, nullptr, &error);
}

void VaultManager::ChangeChunkstorePath(VaultInfo vault_info) {
  // TODO(Fraser#5#): 2014-05-13 - Handle sending a "MoveChunkstoreRequest" to avoid stopping then
  //                               restarting the vault.
  SendVaultShutdownRequest(vault_info.tcp_connection);
  ProcessManager::OnExitFunctor on_exit{ [this, vault_info](maidsafe_error error, int exit_code) {
    LOG(kVerbose) << "Process returned " << exit_code << " with error message: " << error.what();
    process_manager_.AddProcess(std::move(vault_info));
    config_file_handler_.WriteConfigFile(process_manager_.GetAll());
  } };
  process_manager_.StopProcess(vault_info.tcp_connection, on_exit);
}

void VaultManager::HandleVaultStarted(TcpConnectionPtr connection, const std::string& message) {
  RemoveFromNewConnections(connection);
  protobuf::VaultStarted vault_started{ ParseProto<protobuf::VaultStarted>(message) };
  VaultInfo vault_info{
      process_manager_.HandleVaultStarted(connection, { vault_started.process_id() }) };

  // Send vault its credentials
  SendVaultStartedResponse(vault_info, config_file_handler_.SymmKey(),
      config_file_handler_.SymmIv(), routing::ReadBootstrapFile(kBootstrapFilePath_));

  // If the corresponding client is connected, send it the credentials too
  if (vault_info.owner_name->IsInitialised()) {
    try {
      TcpConnectionPtr client{ client_connections_.FindValidated(vault_info.owner_name) };
      SendVaultRunningResponse(client, vault_info.label, vault_info.pmid_and_signer.get());
    }
    catch (const std::exception&) {}  // We don't care if the client isn't connected.
  }
}

void VaultManager::HandleJoinedNetwork(TcpConnectionPtr connection) {
  try {
    VaultInfo vault_info(process_manager_.Find(connection));
    // TODO(Prakash) do vault_info need joined field
    std::string log_message("Vault running as " +
                              HexSubstr(vault_info.pmid_and_signer->first.name().value));
    LOG(kInfo) << log_message;
    TcpConnectionPtr client{ client_connections_.FindValidated(vault_info.owner_name) };
    SendLogMessage(client, log_message);
  }
  catch (const std::exception&) {}  // We don't care if the client isn't connected.
}

void VaultManager::HandleLogMessage(TcpConnectionPtr connection, const std::string& message) {
  LOG(kInfo) << message;
  try {
    VaultInfo vault_info(process_manager_.Find(connection));
    TcpConnectionPtr client{ client_connections_.FindValidated(vault_info.owner_name) };
    SendLogMessage(client, message);
  }
  catch (const std::exception&) {}  // We don't care if the client isn't connected.
}

void VaultManager::RemoveFromNewConnections(TcpConnectionPtr connection) {
  std::lock_guard<std::mutex> lock{ new_connections_mutex_ };
  if (!new_connections_.erase(connection)) {
    LOG(kWarning) << "Connection not found in new_connections_.";
    BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::connection_not_found));
  }
}

}  // namespace vault_manager

}  // namespace maidsafe
