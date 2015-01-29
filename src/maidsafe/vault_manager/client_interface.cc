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
#include "maidsafe/vault_manager/rpc_helper.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/messages/challenge.h"
#include "maidsafe/vault_manager/messages/challenge_response.h"
#include "maidsafe/vault_manager/messages/log_message.h"
#include "maidsafe/vault_manager/messages/network_stable_request.h"
#include "maidsafe/vault_manager/messages/set_network_as_stable.h"
#include "maidsafe/vault_manager/messages/start_vault_request.h"
#include "maidsafe/vault_manager/messages/take_ownership_request.h"
#include "maidsafe/vault_manager/messages/validate_connection_request.h"
#include "maidsafe/vault_manager/messages/vault_running_response.h"

namespace maidsafe {

namespace vault_manager {

ClientInterface::ClientInterface(const passport::Maid& maid)
    : kMaid_(maid),
      mutex_(),
      on_challenge_(),
      network_stable_(),
      network_stable_flag_(),
      asio_service_(1),
      strand_(asio_service_.service()),
      tcp_connection_(ConnectToVaultManager()),
      connection_closer_([&] { tcp_connection_->Close(); }) {
  Send(tcp_connection_, ValidateConnectionRequest());
  auto challenge = SetResponseCallback<std::unique_ptr<asymm::PlainText>, Challenge>(
                       on_challenge_, asio_service_.service(), mutex_).get();
  Send(tcp_connection_, ChallengeResponse(passport::PublicMaid(kMaid_),
                                          asymm::Sign(*challenge, kMaid_.private_key())));
}

ClientInterface::~ClientInterface() {
// Ensure promise is set if required.
#ifdef TESTING
  HandleNetworkStableResponse();
#endif
}

std::shared_ptr<tcp::Connection> ClientInterface::ConnectToVaultManager() {
  unsigned attempts{0};
  tcp::Port initial_port{GetInitialListeningPort()};
  tcp::Port port{initial_port};
  while (attempts <= tcp::kMaxRangeAboveDefaultPort &&
         port <= std::numeric_limits<tcp::Port>::max()) {
    try {
      tcp::ConnectionPtr tcp_connection{tcp::Connection::MakeShared(strand_, port)};
      tcp_connection->Start(
          [this](tcp::Message message) { HandleReceivedMessage(std::move(message)); },
          [this] {});  // FIXME OnConnectionClosed
      LOG(kSuccess) << "Connected to VaultManager which is listening on port " << port;
      return tcp_connection;
    } catch (const std::exception&) {
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
  Send(tcp_connection_, TakeOwnershipRequest(label, vault_dir, max_disk_usage));
  return AddVaultRequest(label);
}

#ifdef USE_VLOGGING
std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
    const std::string& vlog_session_id) {
  NonEmptyString label{GenerateLabel()};
  StartVaultRequest start_vault_request(label, vault_dir, max_disk_usage);
  start_vault_request.vlog_session_id = vlog_session_id;
  Send(tcp_connection_, std::move(start_vault_request));
  return AddVaultRequest(label);
}
#else
std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage) {
  NonEmptyString label{GenerateLabel()};
  Send(tcp_connection_, StartVaultRequest(label, vault_dir, max_disk_usage));
  return AddVaultRequest(label);
}
#endif

std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::AddVaultRequest(
    const NonEmptyString& label) {
  std::shared_ptr<VaultRequest> request(
      std::make_shared<VaultRequest>(asio_service_.service(), std::chrono::seconds(30)));
  request->timer.async_wait([request, label, this](const std::error_code& ec) {
    if (ec && ec == asio::error::operation_aborted)
      return;
    LOG(kWarning) << "Timer expired - i.e. timed out for label: " << label.string();
    std::lock_guard<std::mutex> lock{mutex_};
    if (ec)
      request->SetException(ec);
    else
      request->SetException(MakeError(VaultManagerErrors::timed_out));
    ongoing_vault_requests_.erase(label);
  });

  std::lock_guard<std::mutex> lock{mutex_};
  ongoing_vault_requests_.insert(std::make_pair(label, request));
  return request->promise.get_future();
}

void ClientInterface::HandleReceivedMessage(tcp::Message&& message) {
  try {
    InputVectorStream binary_input_stream(std::move(message));
    MessageTag tag(static_cast<MessageTag>(-1));
    Parse(binary_input_stream, tag);
    switch (tag) {
      case MessageTag::kChallenge:
        InvokeCallBack(Parse<Challenge>(binary_input_stream), on_challenge_);
        break;
      case MessageTag::kVaultRunningResponse:
        HandleVaultRunningResponse(Parse<VaultRunningResponse>(binary_input_stream));
        break;
#ifdef TESTING
      case MessageTag::kNetworkStableResponse:
        HandleNetworkStableResponse();
        break;
#endif
      case MessageTag::kLogMessage:
        HandleLogMessage(Parse<LogMessage>(binary_input_stream));
        break;
      default:
        return;
    }
  } catch (const std::exception& e) {
    LOG(kError) << "Failed to handle incoming message: " << boost::diagnostic_information(e);
  }
}

void ClientInterface::HandleVaultRunningResponse(VaultRunningResponse&& vault_running_response) {
  NonEmptyString label(vault_running_response.vault_label);
  std::unique_ptr<passport::PmidAndSigner> pmid_and_signer;
  std::unique_ptr<maidsafe_error> error;
  if (vault_running_response.vault_keys) {
    pmid_and_signer = maidsafe::make_unique<passport::PmidAndSigner>(
        *vault_running_response.vault_keys->pmid_and_signer);
  } else if (vault_running_response.error) {
    error = maidsafe::make_unique<maidsafe_error>(*vault_running_response.error);
    LOG(kError) << "Got error for vault label: " << label.string() << "   Error: " << error->what();
  } else {
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }

  std::lock_guard<std::mutex> lock{mutex_};
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

void ClientInterface::InvokeCallBack(Challenge&& challenge,
                                     std::function<void(Challenge&&)>& callback) {
  if (callback)
    callback(std::move(challenge));
  else
    LOG(kWarning) << "Call back not available";
}

void ClientInterface::HandleLogMessage(LogMessage&& log_message) { LOG(kInfo) << log_message.data; }

#ifdef TESTING
void ClientInterface::SetTestEnvironment(tcp::Port test_vault_manager_port,
                                         boost::filesystem::path test_env_root_dir,
                                         boost::filesystem::path path_to_vault,
                                         int pmid_list_size) {
  test::SetEnvironment(test_vault_manager_port, test_env_root_dir, path_to_vault, pmid_list_size);
}

#ifdef USE_VLOGGING
std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
    const std::string& vlog_session_id, bool send_hostname_to_visualiser_server) {
  NonEmptyString label{GenerateLabel()};
  StartVaultRequest start_vault_request(label, vault_dir, max_disk_usage);
  start_vault_request.vlog_session_id = vlog_session_id;
  start_vault_request.send_hostname_to_visualiser_server = send_hostname_to_visualiser_server;
  Send(tcp_connection_, std::move(start_vault_request));
  return AddVaultRequest(label);
}

std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
    const std::string& vlog_session_id, bool send_hostname_to_visualiser_server,
    int pmid_list_index) {
  NonEmptyString label{GenerateLabel()};
  StartVaultRequest start_vault_request(label, vault_dir, max_disk_usage);
  start_vault_request.vlog_session_id = vlog_session_id;
  start_vault_request.send_hostname_to_visualiser_server = send_hostname_to_visualiser_server;
  start_vault_request.pmid_list_index = pmid_list_index;
  Send(tcp_connection_, std::move(start_vault_request));
  return AddVaultRequest(label);
}
#else
std::future<std::unique_ptr<passport::PmidAndSigner>> ClientInterface::StartVault(
    const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage, int pmid_list_index) {
  NonEmptyString label{GenerateLabel()};
  StartVaultRequest start_vault_request(label, vault_dir, max_disk_usage);
  start_vault_request.pmid_list_index = pmid_list_index;
  Send(tcp_connection_, std::move(start_vault_request));
  return AddVaultRequest(label);
}
#endif

void ClientInterface::MarkNetworkAsStable() { Send(tcp_connection_, SetNetworkAsStable()); }

std::future<void> ClientInterface::WaitForStableNetwork() {
  Send(tcp_connection_, NetworkStableRequest());
  return network_stable_.get_future();
}
#endif

}  // namespace vault_manager

}  // namespace maidsafe
