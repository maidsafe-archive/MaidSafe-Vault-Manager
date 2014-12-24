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
#include "maidsafe/common/config.h"
#include "maidsafe/common/tcp/connection.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/dispatcher.h"
#include "maidsafe/vault_manager/interprocess_messages.pb.h"
#include "maidsafe/vault_manager/rpc_helper.h"
#include "maidsafe/vault_manager/utils.h"

namespace maidsafe {

namespace vault_manager {

namespace {

std::unique_ptr<passport::PmidAndSigner> ParseVaultKeys(
    protobuf::VaultRunningResponse::VaultKeys vault_keys) {
  crypto::AES256Key symm_key{ vault_keys.aes256key() };
  crypto::AES256InitialisationVector symm_iv{ vault_keys.aes256iv() };
  std::unique_ptr<passport::PmidAndSigner> pmid_and_signer =
      maidsafe::make_unique<passport::PmidAndSigner>(std::make_pair(
          passport::DecryptPmid(
              crypto::CipherText{ NonEmptyString{ vault_keys.encrypted_pmid() } }, symm_key,
                  symm_iv),
          passport::DecryptAnpmid(
              crypto::CipherText{ NonEmptyString{ vault_keys.encrypted_anpmid() } }, symm_key,
                  symm_iv)));
  return pmid_and_signer;
}

}  // unnamed namespace

ClientInterface::ClientInterface(const passport::Maid& maid)
    : kMaid_(maid),
      mutex_(),
      on_challenge_(),
      network_stable_(),
      network_stable_flag_(),
      asio_service_(1),
      tcp_connection_(ConnectToVaultManager()),
      connection_closer_([&] { tcp_connection_->Close(); }) {
  SendValidateConnectionRequest(tcp_connection_);
  auto challenge = SetResponseCallback<std::unique_ptr<asymm::PlainText>>(
                   on_challenge_, asio_service_.service(), mutex_).get();
  SendChallengeResponse(tcp_connection_, passport::PublicMaid(kMaid_),
                        asymm::Sign(*challenge, kMaid_.private_key()));
}

ClientInterface::~ClientInterface() {
  // Ensure promise is set if required.
#ifdef TESTING
  HandleNetworkStableResponse();
#endif
}

std::shared_ptr<tcp::Connection> ClientInterface::ConnectToVaultManager() {
  unsigned attempts{ 0 };
  tcp::Port initial_port{ GetInitialListeningPort() };
  tcp::Port port{ initial_port };
  while (attempts <= tcp::kMaxRangeAboveDefaultPort &&
         port <= std::numeric_limits<tcp::Port>::max()) {
    try {
      tcp::ConnectionPtr tcp_connection{ tcp::Connection::MakeShared(asio_service_, port) };
      tcp_connection->Start([this](std::string message) { HandleReceivedMessage(message); },
                            [this] {});  // FIXME OnConnectionClosed
      LOG(kSuccess) << "Connected to VaultManager which is listening on port " << port;
      return tcp_connection;
    } catch (const std::exception& e) {
      LOG(kVerbose) << "Failed to connect to VaultManager with attempted port " << port
                    << ": " << boost::diagnostic_information(e);
      ++attempts;
      ++port;
    }
  }
  LOG(kError) << "Failed to connect to VaultManager.  Attempted port range " << initial_port
              << " to " << --port;
  BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::failed_to_connect));
}

std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::TakeOwnership(
    const NonEmptyString& label, const boost::filesystem::path& vault_dir,
    DiskUsage max_disk_usage) {
  SendTakeOwnershipRequest(tcp_connection_, label, vault_dir, max_disk_usage);
  return AddVaultRequest(label);
}

#ifdef USE_VLOGGING
std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
    const std::string& vlog_session_id) {
  NonEmptyString label{ GenerateLabel() };
  SendStartVaultRequest(tcp_connection_, label, vault_dir, max_disk_usage, vlog_session_id);
  return AddVaultRequest(label);
}
#else
std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage) {
  NonEmptyString label{ GenerateLabel() };
  SendStartVaultRequest(tcp_connection_, label, vault_dir, max_disk_usage);
  return AddVaultRequest(label);
}
#endif

std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::AddVaultRequest(
    const NonEmptyString& label) {
  LOG(kVerbose) << "ClientInterface::AddVaultRequest : " << label.string();
  std::shared_ptr<VaultRequest> request(std::make_shared<VaultRequest>(asio_service_.service(),
                                                                       std::chrono::seconds(30)));
  request->timer.async_wait([request, label, this](const boost::system::error_code& ec) {
    if (ec && ec == boost::asio::error::operation_aborted) {
      LOG(kVerbose) << "Timer cancelled. OK";
      return;
    }
    LOG(kWarning) << "Timer expired - i.e. timed out for label: " << label.string();
    std::lock_guard<std::mutex> lock{ mutex_ };
    if (ec)
      request->SetException(ec);
    else
      request->SetException(MakeError(VaultManagerErrors::timed_out));
    ongoing_vault_requests_.erase(label);
  });

  std::lock_guard<std::mutex> lock{ mutex_ };
  LOG(kVerbose) << "Added request for vault label:" << label.string();
  ongoing_vault_requests_.insert(std::make_pair(label, request));
  return request->promise.get_future();
}

void ClientInterface::HandleReceivedMessage(const std::string& wrapped_message) {
  try {
    MessageAndType message_and_type{ UnwrapMessage(wrapped_message) };
    LOG(kVerbose) << "Received " << message_and_type.second;
    switch (message_and_type.second) {
      case MessageType::kChallenge:
        InvokeCallBack(message_and_type.first, on_challenge_);
        break;
      case MessageType::kVaultRunningResponse:
        HandleVaultRunningResponse(message_and_type.first);
        break;
#ifdef TESTING
      case MessageType::kNetworkStableResponse:
        HandleNetworkStableResponse();
        break;
#endif
      case MessageType::kLogMessage:
        HandleLogMessage(message_and_type.first);
        break;
      default:
        return;
    }
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to handle incoming message: " << boost::diagnostic_information(e);
  }
}

void ClientInterface::HandleVaultRunningResponse(const std::string& message) {
  protobuf::VaultRunningResponse
    vault_running_response{ ParseProto<protobuf::VaultRunningResponse>(message) };
  NonEmptyString label(vault_running_response.label());
  std::unique_ptr<passport::PmidAndSigner> pmid_and_signer;
  std::unique_ptr<maidsafe_error> error;
  if (vault_running_response.has_vault_keys()) {
    pmid_and_signer = ParseVaultKeys(vault_running_response.vault_keys());
    LOG(kVerbose) << "Got pmid_and_signer for vault label: " << label.string();
  } else if (vault_running_response.has_serialised_maidsafe_error()) {
    SerialisedData serialised_error{std::begin(vault_running_response.serialised_maidsafe_error()),
                                    std::end(vault_running_response.serialised_maidsafe_error())};
    error = maidsafe::make_unique<maidsafe_error>(Parse<maidsafe_error>(serialised_error));
    LOG(kError) << "Got error for vault label: " << label.string()
                << "   Error: " << error->what();
  } else {
    throw MakeError(CommonErrors::invalid_parameter);
  }

  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr = ongoing_vault_requests_.find(label);
  if (ongoing_vault_requests_.end() != itr) {
    if (pmid_and_signer)
      itr->second->SetValue(std::move(pmid_and_signer));
    else
      itr->second->SetException(*error);

    itr->second->timer.cancel();
    ongoing_vault_requests_.erase(itr);
  } else {
    LOG(kWarning) << "No pending requests in map";
  }
}

#ifdef TESTING
void ClientInterface::HandleNetworkStableResponse() {
  std::call_once(network_stable_flag_, [&] { network_stable_.set_value(); });
}
#endif

void ClientInterface::InvokeCallBack(const std::string& message,
                                     std::function<void(std::string)>& callback) {
  if (callback) {
    callback(message);
  } else {
    LOG(kWarning) << "Call back not available";
  }
}

void ClientInterface::HandleLogMessage(const std::string& message) {
  LOG(kInfo) << message;
}

#ifdef TESTING
void ClientInterface::SetTestEnvironment(tcp::Port test_vault_manager_port,
    boost::filesystem::path test_env_root_dir, boost::filesystem::path path_to_vault,
    int pmid_list_size) {
  test::SetEnvironment(test_vault_manager_port, test_env_root_dir, path_to_vault, pmid_list_size);
}

#ifdef USE_VLOGGING
std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
    const std::string& vlog_session_id, bool send_hostname_to_visualiser_server) {
  NonEmptyString label{ GenerateLabel() };
  SendStartVaultRequest(tcp_connection_, label, vault_dir, max_disk_usage, vlog_session_id,
                        send_hostname_to_visualiser_server);
  return AddVaultRequest(label);
}

std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
    const std::string& vlog_session_id, bool send_hostname_to_visualiser_server,
    int pmid_list_index) {
  NonEmptyString label{ GenerateLabel() };
  SendStartVaultRequest(tcp_connection_, label, vault_dir, max_disk_usage, vlog_session_id,
                        send_hostname_to_visualiser_server, pmid_list_index);
  return AddVaultRequest(label);
}
#else
std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage, int pmid_list_index) {
  NonEmptyString label{ GenerateLabel() };
  SendStartVaultRequest(tcp_connection_, label, vault_dir, max_disk_usage, pmid_list_index);
  return AddVaultRequest(label);
}
#endif

void ClientInterface::MarkNetworkAsStable() { SendMarkNetworkAsStableRequest(tcp_connection_); }

std::future<void> ClientInterface::WaitForStableNetwork() {
  SendNetworkStableRequest(tcp_connection_);
  return network_stable_.get_future();
}
#endif

}  // namespace vault_manager

}  // namespace maidsafe
