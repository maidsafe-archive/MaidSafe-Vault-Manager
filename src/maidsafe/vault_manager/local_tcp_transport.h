/*  Copyright 2012 MaidSafe.net limited

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

#ifndef MAIDSAFE_VAULT_MANAGER_LOCAL_TCP_TRANSPORT_H_
#define MAIDSAFE_VAULT_MANAGER_LOCAL_TCP_TRANSPORT_H_

#include <cstdint>
#include <memory>
#include <set>
#include <string>
#include <mutex>
#include <condition_variable>

#include "boost/asio/io_service.hpp"
#include "boost/asio/strand.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/signals2/signal.hpp"

namespace maidsafe {

namespace vault_manager {

class TcpConnection;

typedef uint16_t Port;
typedef boost::signals2::signal<void(const std::string&, Port)> OnMessageReceived;
typedef boost::signals2::signal<void(int)> OnError;  // NOLINT

class LocalTcpTransport : public std::enable_shared_from_this<LocalTcpTransport> {
 public:
  typedef int32_t DataSize;

  explicit LocalTcpTransport(boost::asio::io_service& asio_service);  // NOLINT (Fraser)
  ~LocalTcpTransport();
  Port StartListening(Port port, int& result);
  void StopListening();
  void Connect(Port server_port, int& result);
  void Send(const std::string& data, Port port);
  OnMessageReceived& on_message_received() { return on_message_received_; }
  OnError& on_error() { return on_error_; }
  static DataSize kMaxTransportMessageSize() { return 67108864; }

  friend class TcpConnection;

 private:
  LocalTcpTransport(const LocalTcpTransport&);
  LocalTcpTransport& operator=(const LocalTcpTransport&);

  typedef std::shared_ptr<TcpConnection> ConnectionPtr;
  typedef std::set<ConnectionPtr> ConnectionSet;

  void DoStartListening(Port port, int* result);
  void HandleAccept(boost::asio::ip::tcp::acceptor& acceptor, ConnectionPtr connection,
                    const boost::system::error_code& ec);
  void DoConnect(Port server_port, int* result);
  void DoSend(const std::string& data, Port port);

  void InsertConnection(ConnectionPtr connection);
  void DoInsertConnection(ConnectionPtr connection);
  void RemoveConnection(ConnectionPtr connection);
  void DoRemoveConnection(ConnectionPtr connection);

  boost::asio::io_service& asio_service_;
  OnMessageReceived on_message_received_;
  OnError on_error_;
  boost::asio::ip::tcp::acceptor acceptor_;
  // Because the connections can be in an idle initial state with no pending
  // async operations (after calling PrepareSend()), they are kept alive with
  // a shared_ptr in this map, as well as in the async operation handlers.
  ConnectionSet connections_;
  boost::asio::io_service::strand strand_;
  std::mutex mutex_;
  std::condition_variable cond_var_;
  bool done_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_LOCAL_TCP_TRANSPORT_H_
