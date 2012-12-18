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

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_LOCAL_TCP_TRANSPORT_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_LOCAL_TCP_TRANSPORT_H_

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

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_LOCAL_TCP_TRANSPORT_H_
