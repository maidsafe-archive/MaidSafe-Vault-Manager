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

#ifndef MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_
#define MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "boost/date_time/posix_time/posix_time_config.hpp"
#include "boost/system/error_code.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/thread.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

struct Info;
class TcpTransport;
class MessageHandler;

/*enum class ProcessStatus {
  Running,
  Stopped,
  Crashed
};

enum class ProcessInstruction {
  kRun = 1,
  kStop = 2,
  kTerminate = 3,
  kInvalid = 4
};

enum class KeysStatus {
  kDoNotNeedKeys = 1,
  kNeedKeys = 2,
  kCanHaveKeys = 3,
  kDoHaveKeys = 4
};*/

class VaultController {
 public:
  VaultController();
  ~VaultController();

  bool Start(const std::string& vault_manager_id, std::function<void()> stop_callback);
  bool GetIdentity(asymm::Keys* keys, std::string* account_name);
  void ConfirmJoin(bool joined);

 private:
  VaultController(const VaultController&);
  VaultController& operator=(const VaultController&);
  void ReceiveKeys();
  void ReceiveKeysCallback(const std::string& serialised_info,
                           const Info& sender_info,
                           std::string* /*response*/);
  void ListenForShutdown();
  void ListenForShutdownCallback(const std::string& serialised_response,
                                 const Info& sender_info,
                                 std::string* /*response*/);
  void HandleIncomingMessage(const int& type,
                             const std::string& payload,
                             const Info& info,
                             std::string* response,
                             std::shared_ptr<TcpTransport> transport,
                             std::shared_ptr<MessageHandler> message_handler);
  void ResetTransport(std::shared_ptr<TcpTransport>& transport,
                      std::shared_ptr<MessageHandler>& message_handler);

  std::string process_id_;
  uint16_t port_;
  boost::thread thread_;
  AsioService asio_service_;
  bool check_finished_;
  asymm::Keys keys_;
  std::string account_name_;
  bool info_received_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  bool started_;
  boost::mutex shutdown_mutex_;
  boost::condition_variable shutdown_cond_var_;
  bool shutdown_confirmed_;
  std::function<void()> stop_callback_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_
