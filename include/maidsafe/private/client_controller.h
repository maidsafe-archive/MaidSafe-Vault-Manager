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

#ifndef MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_
#define MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_

#include <condition_variable>
#include <mutex>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

#include "boost/asio/ip/udp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/signals2/connection.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

class LocalTcpTransport;

typedef boost::signals2::signal<void(const std::string&)> OnNewVersionAvailable;


class ClientController {
 public:
  ClientController();
  ~ClientController();

  // Blocking call to start a vault with the specified identity information and account name.
  bool StartVault(const asymm::Keys& keys,
                  const std::string& account_name,
                  const boost::asio::ip::udp::endpoint& bootstrap_endpoint =
                      boost::asio::ip::udp::endpoint());

  // Blocking call to stop the vault with the specified identity. For authentication, provide data
  // signed wth the vault's private key.
  bool StopVault(const asymm::PlainText& data,
                 const asymm::Signature& signature,
                 const asymm::Identity& identity);

  // Blocking call which attempts to set the VaultManager's update interval.  The limits are defined
  // in VaultManager::kMinUpdateInterval() and VaultManager::kMaxUpdateInterval().
  bool SetUpdateInterval(const boost::posix_time::seconds& update_interval);

  // Blocking call which returns the VaultManager's current interval between update checks.  If the
  // call fails, boost::posix_time::pos_infin is returned.
  boost::posix_time::time_duration GetUpdateInterval();

  // Returns reference to signal which will be fired when a new version of the client software is
  // available.  The slot will be passed the filename of the new version.
  OnNewVersionAvailable& on_new_version_available() { return on_new_version_available_; }

 private:
  typedef std::shared_ptr<LocalTcpTransport> TransportPtr;
  ClientController(const ClientController&);
  ClientController& operator=(const ClientController&);
  void ConnectToVaultManager();
  void PingVaultManager(const std::string& random_data,
                        std::shared_ptr<boost::signals2::connection> on_message_received_connection,
                        std::shared_ptr<boost::signals2::connection> on_error_connection);
  void HandlePingResponse(
      const std::string& data_sent,
      const std::string& message,
      uint16_t vault_manager_port,
      std::shared_ptr<boost::signals2::connection> on_message_received_connection,
      std::shared_ptr<boost::signals2::connection> on_error_connection);
  void HandleStartVaultResponse(const std::string& message,
                                const std::function<void(bool)>& callback);  // NOLINT
  boost::posix_time::time_duration SetOrGetUpdateInterval(
      const boost::posix_time::time_duration& update_interval);
  void HandleUpdateIntervalResponse(
      const std::string& message,
      const std::function<void(boost::posix_time::time_duration)>& callback);  // NOLINT
  void HandleReceivedRequest(const std::string& message, uint16_t peer_port);
  void HandleNewVersionAvailable(const std::string& request, std::string& response);

  uint16_t vault_manager_port_;
  AsioService asio_service_;
  TransportPtr receiving_transport_;
  OnNewVersionAvailable on_new_version_available_;
  std::mutex mutex_;
  std::condition_variable cond_var_;
  enum State { kInitialising, kVerified, kFailed } state_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CLIENT_CONTROLLER_H_
