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

#include <algorithm>
#include <chrono>
#include <future>
#include <mutex>
#include <string>
#include <vector>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/tcp_connection.h"
#include "maidsafe/vault_manager/tcp_listener.h"

#include "boost/asio/error.hpp"

namespace maidsafe {

namespace vault_manager {

namespace test {

class Messages {
 public:
  explicit Messages(std::vector<std::string> expected_messages)
      : messages_match_(),
        kExpectedMessages_([&]()->std::vector<std::string> {
          std::sort(std::begin(expected_messages), std::end(expected_messages));
          return expected_messages;
        }()),
        received_messages_(), mutex_() {}

  ~Messages() {
    std::lock_guard<std::mutex> lock{ mutex_ };
    std::sort(std::begin(received_messages_), std::end(received_messages_));
    messages_match_.set_value(received_messages_ == kExpectedMessages_);
  }

  std::future<bool> MessagesMatch() { return messages_match_.get_future(); }

  void AddMessage(std::string message) {
    std::lock_guard<std::mutex> lock{ mutex_ };
    LOG(kVerbose) << message;
    received_messages_.emplace_back(std::move(message));
  }

  size_t ReceivedCount() const {
    std::lock_guard<std::mutex> lock{ mutex_ };
    return received_messages_.size();
  }

  bool WaitForEnoughMessages() const {
    using std::chrono::steady_clock;
    steady_clock::time_point timeout{ steady_clock::now() + std::chrono::milliseconds{ 500 } };
    while (steady_clock::now() < timeout && ReceivedCount() < kExpectedMessages_.size())
      std::this_thread::sleep_for(std::chrono::milliseconds{ 1 });
    return ReceivedCount() == kExpectedMessages_.size();
  }

 private:
  std::promise<bool> messages_match_;
  const std::vector<std::string> kExpectedMessages_;
  std::vector<std::string> received_messages_;
  mutable std::mutex mutex_;
};

TEST(TcpTest, BEH_Basic) {
  const size_t kMessageCount(10);
  std::vector<std::string> to_client_messages, to_server_messages;
  for (size_t i(0); i < kMessageCount; ++i) {
    to_client_messages.emplace_back("Server to client message " + std::to_string(i));
    to_server_messages.emplace_back("Client to server message " + std::to_string(i));
  }

  std::future<bool> messages_received_by_client_match, messages_received_by_server_match;
  AsioService asio_service{ 1 };
  std::promise<TcpConnectionPtr> server_promise;
  TcpListener listener{
      [&](TcpConnectionPtr connection) { server_promise.set_value(std::move(connection)); },
      Port{ 135 } };
  {
    Messages messages_received_by_client{ to_client_messages };
    Messages messages_received_by_server{ to_server_messages };
    messages_received_by_client_match = messages_received_by_client.MessagesMatch();
    messages_received_by_server_match = messages_received_by_server.MessagesMatch();

    TcpConnection client_connection{
        asio_service,
        [&](std::string message) { messages_received_by_client.AddMessage(std::move(message)); },
        [&] { LOG(kVerbose) << "Client connection closed."; },
        listener.ListeningPort() };

    TcpConnectionPtr server_connection{ server_promise.get_future().get() };
    server_connection->Start(
        [&](std::string message) { messages_received_by_server.AddMessage(std::move(message)); },
        [&] { LOG(kVerbose) << "Server connection closed."; });

    std::random_shuffle(std::begin(to_client_messages), std::end(to_client_messages));
    std::random_shuffle(std::begin(to_server_messages), std::end(to_server_messages));
    for (size_t i(0); i < kMessageCount; ++i) {
      server_connection->Send(to_client_messages[i]);
      client_connection.Send(to_server_messages[i]);
    }

    EXPECT_TRUE(messages_received_by_client.WaitForEnoughMessages());
    EXPECT_TRUE(messages_received_by_server.WaitForEnoughMessages());
    // Allow a little extra time to ensure we also check for receiving extra messages.
    Sleep(std::chrono::milliseconds(5));
  }
  EXPECT_TRUE(messages_received_by_client_match.get());
  EXPECT_TRUE(messages_received_by_server_match.get());
}

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe
