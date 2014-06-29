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

#include "maidsafe/vault_manager/vault_interface.h"

#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/transport/tcp_connection.h"

#include "maidsafe/vault_manager/dispatcher.h"
#include "maidsafe/vault_manager/rpc_helper.h"
#include "maidsafe/vault_manager/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

VaultInterface::VaultInterface(transport::Port vault_manager_port)
    : exit_code_promise_(),
      exit_code_flag_(),
      vault_manager_port_(vault_manager_port),
      on_vault_started_response_(),
      vault_config_(),
      asio_service_(1),
      tcp_connection_(transport::TcpConnection::MakeShared(asio_service_, vault_manager_port_)),
      connection_closer_([&] { tcp_connection_->Close(); }) {
  tcp_connection_->Start([this](std::string message) { HandleReceivedMessage(message); },
                         [this] { OnConnectionClosed(); });
  LOG(kSuccess) << "Connected to VaultManager which is listening on port " << vault_manager_port_;
  std::mutex mutex;
  auto vault_config_future(SetResponseCallback<std::unique_ptr<VaultConfig>>(
      on_vault_started_response_, asio_service_.service(), mutex));
  SendVaultStarted(tcp_connection_);
  vault_config_ = vault_config_future.get();
  LOG(kSuccess) << "Retrieved config info from VaultManager";
}

VaultConfig VaultInterface::GetConfiguration() {
  return *vault_config_;
}

int VaultInterface::WaitForExit() {
  return exit_code_promise_.get_future().get();
}

void VaultInterface::SendBootstrapContactToVaultManager(const routing::BootstrapContact& contact) {
  SendBootstrapContact(tcp_connection_, contact);
}

void VaultInterface::SendJoined() {
  SendJoinedNetwork(tcp_connection_);
}

void VaultInterface::OnConnectionClosed() {
  LOG(kError) << "Lost connection to Vault Manager";
  std::call_once(exit_code_flag_, [this] {
      exit_code_promise_.set_value(ErrorToInt(MakeError(VaultManagerErrors::connection_aborted)));
  });
}

void VaultInterface::HandleReceivedMessage(const std::string& wrapped_message) {
  try {
    MessageAndType message_and_type{ UnwrapMessage(wrapped_message) };
    LOG(kVerbose) << "Received " << message_and_type.second;
    switch (message_and_type.second) {
      case MessageType::kVaultStartedResponse:
        HandleVaultStartedResponse(message_and_type.first);
        break;
      case MessageType::kVaultShutdownRequest:
        assert(message_and_type.first.empty());
        HandleVaultShutdownRequest();
        break;
      default:
        return;
    }
  }
  catch (const std::exception& e) {
    LOG(kError) << "Failed to handle incoming message: " << boost::diagnostic_information(e);
  }
}

void VaultInterface::HandleVaultStartedResponse(const std::string& message) {
  if (on_vault_started_response_) {
    on_vault_started_response_(message);
  } else {
    assert(false);  // already received vault configuration
  }
}

void VaultInterface::HandleVaultShutdownRequest() {
  LOG(kInfo) << "Received  ShutdownRequest from Vault Manager";
  std::call_once(exit_code_flag_, [this] { exit_code_promise_.set_value(0); });
}

#ifdef TESTING
void VaultInterface::KillConnection() {
  maidsafe::Sleep(std::chrono::seconds(1));
  tcp_connection_.reset();
}

void VaultInterface::SendInvalidMessage() {
  tcp_connection_->Send("Rubbish");
}

void VaultInterface::StopProcess() {
  maidsafe::Sleep(std::chrono::seconds(1));
  HandleVaultShutdownRequest();
}
#endif

}  // namespace vault_manager

}  // namespace maidsafe
