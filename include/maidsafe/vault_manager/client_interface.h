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

//#include <condition_variable>
#include <cstdint>
//#include <functional>
#include <future>
//#include <map>
#include <memory>
//#include <mutex>
//#include <string>
//#include <utility>
//#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/routing/bootstrap_file_operations.h"

#include "maidsafe/vault_manager/utils.h"

namespace maidsafe {

namespace vault_manager {

class TcpConnection;

class ClientInterface {
 public:
  explicit ClientInterface(const passport::Maid& maid);
  ~ClientInterface();

  std::future<routing::BootstrapContacts> GetBootstrapContacts();

  std::future<passport::PmidAndSigner> TakeOwnership(const std::string& label,
                                                     const boost::filesystem::path& chunkstore,
                                                     DiskUsage max_disk_usage);

  std::future<passport::PmidAndSigner> StartVault(const boost::filesystem::path& chunkstore,
                                                  DiskUsage max_disk_usage);

#ifdef TESTING
  static void SetTestEnvironmentVariables(
      uint16_t test_vault_manager_port, boost::filesystem::path test_env_root_dir,
      boost::filesystem::path path_to_vault,
      routing::BootstrapContacts bootstrap_contacts);
#endif

 private:
  ClientInterface(const ClientInterface&) = delete;
  ClientInterface(ClientInterface&&) = delete;
  ClientInterface& operator=(ClientInterface) = delete;

  //enum State {
  //  kInitialising,
  //  kVerified,
  //  kFailed
  //};

  //bool FindNextAcceptingPort(TransportPtr requesting_transport);
  //bool ConnectToVaultManager(std::string& path_to_new_installer);
  //void HandleRegisterResponse(const std::string& message, Port vault_manager_port,
  //                            std::mutex& mutex, std::condition_variable& condition_variable,
  //                            State& state, std::string& path_to_new_installer);
  //template <typename ResponseType>
  //void HandleStartStopVaultResponse(const std::string& message,
  //                                  const std::function<void(bool)>& callback);
  //boost::posix_time::time_duration SetOrGetUpdateInterval(
  //    const boost::posix_time::time_duration& update_interval);
  //void HandleUpdateIntervalResponse(
  //    const std::string& message,
  //    const std::function<void(boost::posix_time::time_duration)>& callback);
  //void HandleReceivedRequest(const std::string& message, Port peer_port);
  //void HandleNewVersionAvailable(const std::string& request, std::string& response);
  //void HandleVaultJoinConfirmation(const std::string& request, std::string& response);
  //void HandleBootstrapResponse(const std::string& message,
  //                             std::vector<boost::asio::ip::udp::endpoint>& bootstrap_endpoints,
  //                             std::function<void(bool)> callback);
  void HandleReceivedMessage(const std::string& wrapped_message);

  passport::Maid maid_;
  AsioService asio_service_;
  std::shared_ptr<TcpConnection> tcp_connection_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_CLIENT_INTERFACE_H_
