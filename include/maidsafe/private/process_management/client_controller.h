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
#include <mutex>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <map>

#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

namespace process_management {

class LocalTcpTransport;

typedef boost::signals2::signal<void(const std::string&)> OnNewVersionAvailable;


class ClientController {
 public:
  ClientController();
  ~ClientController();

  // Blocking call to start a vault with the specified identity information and account name.
  bool StartVault(const asymm::Keys& keys, const std::string& account_name);

  // Blocking call to stop the vault with the specified identity. For authentication, provide data
  // signed wth the vault's private key.
  bool StopVault(const asymm::PlainText& data,
                 const asymm::Signature& signature,
                 const asymm::Identity& identity);

  // Blocking call which attempts to set the Invigilator's update interval.  The limits are
  // defined in Invigilator::kMinUpdateInterval() and Invigilator::kMaxUpdateInterval().
  bool SetUpdateInterval(const boost::posix_time::seconds& update_interval);

  // Blocking call which returns the Invigilator's current interval between update checks.  If the
  // call fails, boost::posix_time::pos_infin is returned.
  boost::posix_time::time_duration GetUpdateInterval();


  // Returns reference to signal which will be fired when a new version of the client software is
  // available.  The slot will be passed the filename of the new version.
  OnNewVersionAvailable& on_new_version_available() { return on_new_version_available_; }

 private:
  typedef std::shared_ptr<LocalTcpTransport> TransportPtr;

  ClientController(const ClientController&);
  ClientController& operator=(const ClientController&);

  void ConnectToInvigilator();
  void RegisterWithInvigilator(uint16_t client_port, TransportPtr request_transport);
  void HandleRegisterResponse(const std::string& message,
                          uint16_t invigilator_port,
                          uint16_t client_port,
                          TransportPtr request_transport);
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

  uint16_t invigilator_port_, local_port_;
  AsioService asio_service_;
  TransportPtr receiving_transport_;
  OnNewVersionAvailable on_new_version_available_;
  std::mutex mutex_;
  std::condition_variable cond_var_;
  enum State { kInitialising, kVerified, kFailed } state_;
  std::string bootstrap_nodes_;
  std::map<asymm::Identity, bool> joining_vaults_;
};

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_PROCESS_MANAGEMENT_CLIENT_CONTROLLER_H_
