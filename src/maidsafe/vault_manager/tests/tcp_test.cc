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
#include <array>
#include <chrono>
#include <future>
#include <mutex>
#include <string>
#include <vector>

#include "boost/asio/buffer.hpp"
#include "boost/asio/error.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/asio/write.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/tcp_connection.h"
#include "maidsafe/vault_manager/tcp_listener.h"


namespace maidsafe {

namespace vault_manager {

namespace test {

class Messages {
 public:
  enum class Status { kSuccess, kMismatch, kTimedOut };
  explicit Messages(std::vector<std::string> expected_messages)
      : kExpectedMessages_([&]()->std::vector<std::string> {
          std::sort(std::begin(expected_messages), std::end(expected_messages));
          return expected_messages;
        }()),
        received_messages_(), mutex_() {}

  Status MessagesMatch() {
    if (!WaitForEnoughMessages()) {
      LOG(kError) << "Timed out waiting for messages.";
      return Status::kTimedOut;
    }
    std::lock_guard<std::mutex> lock{ mutex_ };
    std::sort(std::begin(received_messages_), std::end(received_messages_));
    return received_messages_ == kExpectedMessages_ ? Status::kSuccess : Status::kMismatch;
  }

  void AddMessage(std::string message) {
    std::lock_guard<std::mutex> lock{ mutex_ };
    received_messages_.emplace_back(std::move(message));
  }

 private:
  size_t ReceivedCount() const {
    std::lock_guard<std::mutex> lock{ mutex_ };
    return received_messages_.size();
  }

  bool WaitForEnoughMessages() const {
    using std::chrono::steady_clock;
    size_t total_messages_size{ 0 };
    for (auto itr(std::begin(kExpectedMessages_)); itr != std::end(kExpectedMessages_); ++itr)
      total_messages_size += itr->size();

    steady_clock::time_point timeout{ steady_clock::now() +
                                      std::chrono::microseconds{ total_messages_size + 1000000U} };
    while (steady_clock::now() < timeout && ReceivedCount() < kExpectedMessages_.size())
      Sleep(std::chrono::milliseconds{ 1 });
    // Allow a little extra time to ensure we also check for receiving extra messages.
    Sleep(std::chrono::milliseconds{ 5 });
    return ReceivedCount() == kExpectedMessages_.size();
  }

  const std::vector<std::string> kExpectedMessages_;
  std::vector<std::string> received_messages_;
  mutable std::mutex mutex_;
};

class TcpTest : public testing::Test {
 protected:
  TcpTest() : to_client_messages_(),
              to_server_messages_(),
              messages_received_by_client_(),
              messages_received_by_server_() {}

  void InitialiseMessagesToClient() {
    messages_received_by_client_ = maidsafe::make_unique<Messages>(to_client_messages_);
  }
  void InitialiseMessagesToServer() {
    messages_received_by_server_ = maidsafe::make_unique<Messages>(to_server_messages_);
  }
  std::vector<std::string> to_client_messages_, to_server_messages_;
  std::unique_ptr<Messages> messages_received_by_client_, messages_received_by_server_;
};

TEST_F(TcpTest, BEH_Basic) {
  const size_t kMessageCount(10);
  to_client_messages_.emplace_back(RandomString(1));
  to_server_messages_.emplace_back(RandomString(1));
  for (size_t i(2); i < kMessageCount; ++i) {
    to_client_messages_.emplace_back(RandomString(i * 100000));
    to_server_messages_.emplace_back(RandomString(i * 100000));
  }
  to_client_messages_.emplace_back(RandomString(TcpConnection::MaxMessageSize()));
  to_server_messages_.emplace_back(RandomString(TcpConnection::MaxMessageSize()));
  InitialiseMessagesToClient();
  InitialiseMessagesToServer();

  AsioService asio_service{ 1 };
  std::promise<TcpConnectionPtr> server_promise;
  TcpListener listener{
      [&](TcpConnectionPtr connection) { server_promise.set_value(std::move(connection)); },
      Port{ 7777 } };
  TcpConnection client_connection{
      asio_service,
      [&](std::string message) { messages_received_by_client_->AddMessage(std::move(message)); },
      [&] { LOG(kVerbose) << "Client connection closed."; },
      listener.ListeningPort() };

  TcpConnectionPtr server_connection{ server_promise.get_future().get() };
  server_connection->Start(
      [&](std::string message) { messages_received_by_server_->AddMessage(std::move(message)); },
      [&] { LOG(kVerbose) << "Server connection closed."; });

  std::random_shuffle(std::begin(to_client_messages_), std::end(to_client_messages_));
  std::random_shuffle(std::begin(to_server_messages_), std::end(to_server_messages_));
  for (size_t i(0); i < kMessageCount; ++i) {
    server_connection->Send(to_client_messages_[i]);
    client_connection.Send(to_server_messages_[i]);
  }
  EXPECT_EQ(messages_received_by_client_->MessagesMatch(), Messages::Status::kSuccess);
  EXPECT_EQ(messages_received_by_server_->MessagesMatch(), Messages::Status::kSuccess);
}

TEST_F(TcpTest, BEH_UnavailablePort) {
  to_client_messages_.emplace_back(RandomString(1000));
  to_server_messages_.emplace_back(RandomString(1000));
  InitialiseMessagesToClient();
  InitialiseMessagesToServer();

  AsioService asio_service{ 1 };
  std::promise<TcpConnectionPtr> server_promise;
  TcpListener listener0{ [](TcpConnectionPtr /*connection*/) {}, Port{ 7777 } };
  TcpListener listener1{
      [&](TcpConnectionPtr connection) { server_promise.set_value(std::move(connection)); },
      listener0.ListeningPort() };
  TcpConnection client_connection{
      asio_service,
      [&](std::string message) { messages_received_by_client_->AddMessage(std::move(message)); },
      [&] { LOG(kVerbose) << "Client connection closed."; },
      listener1.ListeningPort() };

  TcpConnectionPtr server_connection{ server_promise.get_future().get() };
  server_connection->Start(
      [&](std::string message) { messages_received_by_server_->AddMessage(std::move(message)); },
      [&] { LOG(kVerbose) << "Server connection closed."; });

  server_connection->Send(to_client_messages_.front());
  client_connection.Send(to_server_messages_.front());
  EXPECT_EQ(messages_received_by_client_->MessagesMatch(), Messages::Status::kSuccess);
  EXPECT_EQ(messages_received_by_server_->MessagesMatch(), Messages::Status::kSuccess);
}

TEST_F(TcpTest, BEH_InvalidMessageSizes) {
  to_client_messages_.emplace_back();
  to_server_messages_.emplace_back();
  to_client_messages_.emplace_back(RandomString(TcpConnection::MaxMessageSize() + 1));
  to_server_messages_.emplace_back(RandomString(TcpConnection::MaxMessageSize() + 1));
  InitialiseMessagesToClient();
  InitialiseMessagesToServer();

  AsioService asio_service{ 1 };
  std::vector<TcpConnectionPtr> server_connections;
  TcpListener listener{
      [&](TcpConnectionPtr connection) {
        LOG(kVerbose) << "Server connection opened.";
        server_connections.push_back(connection);  // Keep connection alive
        connection->Start(
            [&](std::string msg) { messages_received_by_server_->AddMessage(std::move(msg)); },
            [&] { LOG(kVerbose) << "Server connection closed."; });
        for (const auto& message : to_client_messages_)
          EXPECT_THROW(connection->Send(message), maidsafe_error);
      },
      Port{ 7777 } };
  TcpConnection client_connection{
      asio_service,
      [&](std::string message) { messages_received_by_client_->AddMessage(std::move(message)); },
      [&] { LOG(kVerbose) << "Client connection closed."; },
      listener.ListeningPort() };

  EXPECT_THROW(client_connection.Send(to_server_messages_[0]), maidsafe_error);
  EXPECT_THROW(client_connection.Send(to_server_messages_[1]), maidsafe_error);
  EXPECT_EQ(messages_received_by_client_->MessagesMatch(), Messages::Status::kTimedOut);
  EXPECT_EQ(messages_received_by_server_->MessagesMatch(), Messages::Status::kTimedOut);
  to_client_messages_.clear();

  // Try to make server receive a message which shows its size as too large
  AsioService bad_asio_service{ 1 };
  boost::asio::ip::tcp::socket bad_socket(bad_asio_service.service());
  bad_socket.connect(boost::asio::ip::tcp::endpoint{ boost::asio::ip::address_v6::loopback(),
                                                     listener.ListeningPort() });
  ASSERT_TRUE(bad_socket.is_open());

  to_server_messages_.erase(std::begin(to_server_messages_));
  ASSERT_TRUE(to_server_messages_.size() == 1U);
  ASSERT_TRUE(to_server_messages_.front().size() > TcpConnection::MaxMessageSize());
  InitialiseMessagesToServer();
  const std::string& large_data{ to_server_messages_.front() };

  std::array<unsigned char, 4> size_buffer;
  for (int i = 0; i != 4; ++i)
    size_buffer[i] = static_cast<char>(large_data.size() >> (8 * (3 - i)));

  std::array<boost::asio::const_buffer, 2> buffers;
  buffers[0] = boost::asio::buffer(size_buffer);
  buffers[1] = boost::asio::buffer(large_data.data(), large_data.size());
  EXPECT_THROW(boost::asio::write(bad_socket, buffers), boost::system::system_error);
  EXPECT_EQ(messages_received_by_server_->MessagesMatch(), Messages::Status::kTimedOut);

  // Try to make server receive a message which is too large by lying about its size
  InitialiseMessagesToServer();
  bad_socket = boost::asio::ip::tcp::socket(bad_asio_service.service());
  bad_socket.connect(boost::asio::ip::tcp::endpoint{ boost::asio::ip::address_v6::loopback(),
                     listener.ListeningPort() });
  ASSERT_TRUE(bad_socket.is_open());
  --size_buffer[3];
  buffers[0] = boost::asio::buffer(size_buffer);
  EXPECT_EQ(boost::asio::write(bad_socket, buffers), large_data.size() + 4U);
  EXPECT_EQ(messages_received_by_server_->MessagesMatch(), Messages::Status::kMismatch);
}

TEST_F(TcpTest, BEH_ServerConnectionAborts) {
  to_client_messages_.emplace_back(RandomString(1000));
  to_server_messages_.emplace_back(RandomString(1000));
  InitialiseMessagesToClient();
  InitialiseMessagesToServer();

  AsioService asio_service{ 1 };
  std::promise<TcpConnectionPtr> server_promise;
  TcpListener listener0{ [](TcpConnectionPtr /*connection*/) {}, Port{ 7777 } };
  TcpListener listener1{
      [&](TcpConnectionPtr connection) { server_promise.set_value(std::move(connection)); },
      listener0.ListeningPort() };
  TcpConnection client_connection{
      asio_service,
      [&](std::string message) { messages_received_by_client_->AddMessage(std::move(message)); },
      [&] { LOG(kVerbose) << "Client connection closed."; },
      listener1.ListeningPort() };

  TcpConnectionPtr server_connection{ server_promise.get_future().get() };
  server_connection->Start(
      [&](std::string message) { messages_received_by_server_->AddMessage(std::move(message)); },
      [&] { LOG(kVerbose) << "Server connection closed."; });

  server_connection->Send(to_client_messages_.front());
  client_connection.Send(to_server_messages_.front());
  server_connection.reset();
  EXPECT_EQ(messages_received_by_client_->MessagesMatch(), Messages::Status::kSuccess);
  EXPECT_EQ(messages_received_by_server_->MessagesMatch(), Messages::Status::kSuccess);
}

TEST_F(TcpTest, BEH_ClientConnectionAborts) {
}

TEST_F(TcpTest, BEH_MultipleConnectionsToServer) {
}

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe
