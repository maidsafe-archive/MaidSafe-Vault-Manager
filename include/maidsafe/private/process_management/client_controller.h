/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#ifndef MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_CLIENT_CONTROLLER_H_
#define MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_CLIENT_CONTROLLER_H_

#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <utility>
#include <vector>

#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

struct Fob;

namespace priv {

namespace process_management {

class LocalTcpTransport;

typedef boost::signals2::signal<void(const NonEmptyString&)> OnNewVersionAvailable;
typedef std::pair<std::string, uint16_t> EndPoint;

class ClientController {
 public:
  ClientController(std::function<void(const NonEmptyString&)> on_new_version_available_slot);
  ~ClientController();

  bool BootstrapEndpoints(std::vector<EndPoint>& endpoints);

  // Blocking call to start a vault with the specified identity information and account name.
  bool StartVault(const Fob& fob,
                  const std::string& account_name,
                  const boost::filesystem::path& chunkstore);

  // Blocking call to stop the vault with the specified identity. For authentication, provide data
  // signed wth the vault's private key.
  bool StopVault(const asymm::PlainText& data,
                 const asymm::Signature& signature,
                 const Identity& identity);

  // Blocking call which attempts to set the Invigilator's update interval.  The limits are
  // defined in Invigilator::kMinUpdateInterval() and Invigilator::kMaxUpdateInterval().
  bool SetUpdateInterval(const boost::posix_time::seconds& update_interval);

  // Blocking call which returns the Invigilator's current interval between update checks.  If the
  // call fails, boost::posix_time::pos_infin is returned.
  boost::posix_time::time_duration GetUpdateInterval();

  // Blocking call to retrieve the latest bootstrap nodes from the Invigilator.
  bool GetBootstrapNodes(std::vector<std::pair<std::string, uint16_t> >& bootstrap_endpoints);

 private:
  typedef std::shared_ptr<LocalTcpTransport> TransportPtr;
  enum State { kInitialising, kVerified, kFailed };

  ClientController(const ClientController&);
  ClientController& operator=(const ClientController&);
  bool FindNextAcceptingPort(TransportPtr requesting_transport);
  bool ConnectToInvigilator(std::string& path_to_new_installer);
  bool StartListeningPort();
  void HandleRegisterResponse(const std::string& message,
                              uint16_t invigilator_port,
                              std::mutex& mutex,
                              std::condition_variable& condition_variable,
                              State& state,
                              std::string& path_to_new_installer);
  template<typename ResponseType>
  void HandleStartStopVaultResponse(const std::string& message,
                                    const std::function<void(bool)>& callback);  // NOLINT
  boost::posix_time::time_duration SetOrGetUpdateInterval(
      const boost::posix_time::time_duration& update_interval);
  void HandleUpdateIntervalResponse(
      const std::string& message,
      const std::function<void(boost::posix_time::time_duration)>& callback);  // NOLINT
  void HandleReceivedRequest(const std::string& message, uint16_t peer_port);
  void HandleNewVersionAvailable(const std::string& request, std::string& response);
  void HandleVaultJoinConfirmation(const std::string& request, std::string& response);
  void HandleBootstrapResponse(const std::string& message,
                               std::vector<std::pair<std::string, uint16_t> > &bootstrap_endpoints,
                               std::function<void(bool)> callback);  //NOLINT (Philip)

  uint16_t invigilator_port_, local_port_;
  AsioService asio_service_;
  TransportPtr receiving_transport_;
  OnNewVersionAvailable on_new_version_available_;
  State state_;
  std::vector<EndPoint> bootstrap_nodes_;
  std::map<Identity, bool> joining_vaults_;
  std::mutex joining_vaults_mutex_;
  std::condition_variable joining_vaults_conditional_;
};

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_CLIENT_CONTROLLER_H_
