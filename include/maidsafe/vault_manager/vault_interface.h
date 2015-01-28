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

#ifndef MAIDSAFE_VAULT_MANAGER_VAULT_INTERFACE_H_
#define MAIDSAFE_VAULT_MANAGER_VAULT_INTERFACE_H_

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>

#include "asio/io_service_strand.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/vault_config.h"

namespace maidsafe {

namespace vault_manager {

struct VaultStartedResponse;

class VaultInterface {
 public:
  VaultInterface(const VaultInterface&) = delete;
  VaultInterface(VaultInterface&&) = delete;
  VaultInterface& operator=(VaultInterface) = delete;

  explicit VaultInterface(tcp::Port vault_manager_port);

  VaultConfig GetConfiguration();

  // Doesn't throw.
  int WaitForExit();

  void SendJoined();

#ifdef TESTING
  void KillConnection();
  void SendInvalidMessage();
  void StopProcess();
#endif

 private:
  void HandleReceivedMessage(tcp::Message&& message);
  void OnConnectionClosed();

  void HandleVaultStartedResponse(VaultStartedResponse&& vault_started_response);
  void HandleVaultShutdownRequest();

  std::promise<int> exit_code_promise_;
  std::once_flag exit_code_flag_;
  tcp::Port vault_manager_port_;
  std::function<void(VaultStartedResponse&&)> on_vault_started_response_;
  std::unique_ptr<VaultConfig> vault_config_;
  AsioService asio_service_;
  asio::io_service::strand strand_;
  std::shared_ptr<tcp::Connection> tcp_connection_;
  // We need to ensure the connection is closed in the event of the constructor throwing, or the
  // asio_service destructor will hang.
  on_scope_exit connection_closer_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_INTERFACE_H_
