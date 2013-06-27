/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_LOCAL_TCP_TRANSPORT_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_LOCAL_TCP_TRANSPORT_H_

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

namespace lifestuff_manager {

class TcpConnection;

typedef uint16_t Port;
typedef boost::signals2::signal<void(const std::string&, Port)> OnMessageReceived;
typedef boost::signals2::signal<void(const int&)> OnError;


#ifdef __GNUC__
#  pragma GCC diagnostic push
#  pragma GCC diagnostic ignored "-Weffc++"
#endif
class LocalTcpTransport : public std::enable_shared_from_this<LocalTcpTransport> {
#ifdef __GNUC__
#  pragma GCC diagnostic pop
#endif

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
  void HandleAccept(boost::asio::ip::tcp::acceptor& acceptor,
                    ConnectionPtr connection,
                    const boost::system::error_code& ec);
  void DoConnect(Port server_port, int* result);
  void DoSend(const std::string& data, Port port);

  void InsertConnection(ConnectionPtr connection);
  void DoInsertConnection(ConnectionPtr connection);
  void RemoveConnection(ConnectionPtr connection);
  void DoRemoveConnection(ConnectionPtr connection);

  boost::asio::io_service &asio_service_;
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

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_LOCAL_TCP_TRANSPORT_H_
