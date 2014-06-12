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

#ifndef MAIDSAFE_VAULT_MANAGER_CLIENT_INTERFACE_H_
#define MAIDSAFE_VAULT_MANAGER_CLIENT_INTERFACE_H_

#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/routing/bootstrap_file_operations.h"

#include "maidsafe/vault_manager/rpc_helper.h"
#include "maidsafe/vault_manager/utils.h"

namespace maidsafe {

namespace vault_manager {

class TcpConnection;

class ClientInterface {
 public:
  explicit ClientInterface(const passport::Maid& maid);

  std::future<routing::BootstrapContacts> GetBootstrapContacts();

  std::future<std::unique_ptr<passport::PmidAndSigner>> TakeOwnership(const NonEmptyString& label,
      const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage);

  std::future<std::unique_ptr<passport::PmidAndSigner>> StartVault(
      const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage);

#ifdef TESTING
  // This function sets up global variables specifying:
  // * the desired TCP listening port of the VaultManager (VM)
  // * a root dir for the VM to which it will write its config file and bootstrap list
  // * the path to an executable which the VM will treat as a MaidSafe vault
  // * a bootstrap contact which will be used to initialise the bootstrap list the VM manages
  // * a list of PublicPmids to allow starting a zero-state network
  //
  // 'test_env_root_dir' must exist when this call is made or an error will be thrown.
  // The function should only be called once - further calls are no-ops.
  static void SetTestEnvironment(
      uint16_t test_vault_manager_port, boost::filesystem::path test_env_root_dir,
      boost::filesystem::path path_to_vault, routing::BootstrapContacts bootstrap_contacts,
      int pmid_list_size);

  std::future<std::unique_ptr<passport::PmidAndSigner>> StartVault(
      const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage, int pmid_list_index);
#endif

 private:
  typedef detail::PromiseAndTimer<std::unique_ptr<passport::PmidAndSigner>> VaultRequest;

  ClientInterface(const ClientInterface&) = delete;
  ClientInterface(ClientInterface&&) = delete;
  ClientInterface& operator=(ClientInterface) = delete;

  std::shared_ptr<TcpConnection> ConnectToVaultManager();
  std::future<std::unique_ptr<passport::PmidAndSigner>> AddVaultRequest(
      const NonEmptyString& label);
  void HandleReceivedMessage(const std::string& wrapped_message);
  void HandleVaultRunningResponse(const std::string& message);
  void HandleBootstrapContactsResponse(const std::string& message);
  void InvokeCallBack(const std::string& message, std::function<void(std::string)>& callback);
  void HandleLogMessage(const std::string& message);

  const passport::Maid kMaid_;
  std::mutex mutex_;
  std::function<void(std::string)> on_challenge_;
  std::function<void(std::string)> on_bootstrap_contacts_response_;
  std::map<NonEmptyString, std::shared_ptr<VaultRequest>> ongoing_vault_requests_;
  AsioService asio_service_;
  std::shared_ptr<TcpConnection> tcp_connection_;
  // We need to ensure the connection is closed in the event of the constructor throwing, or the
  // asio_service destructor will hang.
  on_scope_exit connection_closer_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_CLIENT_INTERFACE_H_
