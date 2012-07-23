/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_
#define MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_

#include <boost/interprocess/managed_shared_memory.hpp>
#include <boost/process.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <thread>
#include <string>
#include <vector>

#include "maidsafe/common/rsa.h"

#include "maidsafe/private/tcp_transport.h"
#include "maidsafe/private/message_handler.h"

namespace maidsafe {

namespace priv {

namespace bai = boost::asio::ip;

enum class ProcessStatus {
  Running,
  Stopped,
  Crashed
};

enum ProcessInstruction {
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
};

class VaultController {
 public:
  VaultController();
  ~VaultController();

  bool Start(std::string pid_string, std::function<void()> stop_callback);
  bool GetIdentity(maidsafe::rsa::Keys* keys, std::string* account_name);

 private:
  void ListenForStopTerminate(std::string shared_mem_name,
                              int id,
                              std::function<void()> stop_handler);
  void PrintResult(std::string serv, boost::asio::ip::tcp::resolver::iterator iter,
                   const boost::system::error_code& ec);
  void ReceiveKeys();
  void ReceiveKeysCallback(const int& type, const std::string& payload,
                           const Info& /*sender_info*/);
  void OnMessageReceived(const std::string &request,
                         const Info /*&info*/,
                         std::string */*response*/,
                         Timeout */*timeout*/);
  ProcessInstruction CheckInstruction(const int32_t& id);
  std::string process_id_;
  uint16_t port_;
  boost::thread thd;
  boost::asio::io_service io_service_;
  bai::tcp::resolver resolver_;
  bai::tcp::resolver::query query_;
  bai::tcp::resolver::iterator endpoint_iterator_;
  bai::tcp::socket socket_;
  bool check_finished_;
  maidsafe::rsa::Keys keys_;
  std::string account_name_;
  bool info_received_;
  boost::mutex mutex_;
  boost::condition_variable cond_var_;
  std::shared_ptr<TcpTransport> transport_;
  MessageHandler message_handler_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_VAULT_CONTROLLER_H_
