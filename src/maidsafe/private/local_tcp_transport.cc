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

#include "maidsafe/private/local_tcp_transport.h"

#include <functional>

#include "maidsafe/common/log.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/tcp_connection.h"


namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace priv {

LocalTcpTransport::LocalTcpTransport(boost::asio::io_service &asio_service) // NOLINT
    : asio_service_(asio_service),
      on_message_received_(),
      on_error_(),
      acceptor_(asio_service),
      connections_(),
      strand_(asio_service) {}

LocalTcpTransport::~LocalTcpTransport() {
  for (ConnectionPtr connection : connections_)
    connection->Close();
}

int LocalTcpTransport::StartListening(Port port) {
  if (acceptor_.is_open()) {
    LOG(kError) << "Already listening on port " << port;
    return kAlreadyStarted;
  }

  ip::tcp::endpoint endpoint(ip::address_v4::loopback(), port);

  bs::error_code ec;
  acceptor_.open(endpoint.protocol(), ec);
  if (ec) {
    LOG(kError) << "Could not open the socket: " << ec.message();
    return kInvalidAddress;
  }

// Below option is interprated differently by Windows and shouldn't be used. On,
// Windows, this will allow two processes to listen on same port. On POSIX
// compliant OS, this option tells the kernel that even if given port is busy
// (only TIME_WAIT state), go ahead and reuse it anyway. If it is busy, but with
// another state, you will still get an address already in use error.
// http://msdn.microsoft.com/en-us/library/ms740621(VS.85).aspx
// http://www.unixguide.net/network/socketfaq/4.5.shtml
// http://old.nabble.com/Port-allocation-problem-on-windows-(incl.-patch)-td28241079.html
#ifndef MAIDSAFE_WIN32
  acceptor_.set_option(ip::tcp::acceptor::reuse_address(true), ec);
#endif
  if (ec) {
    LOG(kError) << "Could not set the reuse address option: " << ec.message();
    return kSetOptionFailure;
  }

  acceptor_.bind(endpoint, ec);
  if (ec) {
    LOG(kError) << "Could not bind socket to endpoint: " << ec.message();
    return kBindError;
  }

  acceptor_.listen(asio::socket_base::max_connections, ec);
  if (ec) {
    LOG(kError) << "Could not start listening: " << ec.message();
    return kListenError;
  }

  ConnectionPtr new_connection(new TcpConnection(shared_from_this()));

  // The connection object is kept alive in the acceptor handler until HandleAccept() is called.
  acceptor_.async_accept(new_connection->Socket(),
                         strand_.wrap(std::bind(&LocalTcpTransport::HandleAccept,
                                                shared_from_this(), std::ref(acceptor_),
                                                new_connection, args::_1)));
  return kSuccess;
}

void LocalTcpTransport::StopListening() {
  strand_.dispatch([this] {
    boost::system::error_code ec;
    acceptor_.close(ec);
  });
}

void LocalTcpTransport::HandleAccept(boost::asio::ip::tcp::acceptor& acceptor,
                                     ConnectionPtr connection,
                                     const bs::error_code& ec) {
  if (!acceptor.is_open())
    return;

  if (!ec) {
    // It is safe to call DoInsertConnection directly because HandleAccept() is
    // already being called inside the strand.
    DoInsertConnection(connection);
    connection->StartReceiving();
  }

  ConnectionPtr new_connection(new TcpConnection(shared_from_this()));

  // The connection object is kept alive in the acceptor handler until
  // HandleAccept() is called.
  acceptor.async_accept(new_connection->Socket(),
                        strand_.wrap(std::bind(&LocalTcpTransport::HandleAccept,
                                               shared_from_this(), std::ref(acceptor),
                                               new_connection, args::_1)));
}

int LocalTcpTransport::Connect(Port server_port) {
  if (acceptor_.is_open())
    return kAlreadyStarted;
  ConnectionPtr connection(new TcpConnection(shared_from_this()));
  int result(connection->Connect(server_port));
  if (result == kSuccess)
    InsertConnection(connection);
  return result;
}

void LocalTcpTransport::Send(const std::string& data, Port port) {
  DataSize msg_size(static_cast<DataSize>(data.size()));
  if (msg_size > kMaxTransportMessageSize()) {
    LOG(kError) << "Data size " << msg_size << " bytes (exceeds limit of "
                << kMaxTransportMessageSize() << ")";
    on_error_(kMessageSizeTooLarge);
    return;
  }
  strand_.dispatch(std::bind(&LocalTcpTransport::DoSend, shared_from_this(), data, port));
}

void LocalTcpTransport::DoSend(const std::string& data, Port port) {
  auto itr(std::find_if(connections_.begin(),
                        connections_.end(),
                        [port](ConnectionPtr connection) {
                          return connection->Socket().remote_endpoint().port() == port;
                        }));
  if (itr == connections_.end()) {
    LOG(kError) << "Not connected to port " << port;
    on_error_(kInvalidAddress);
  } else {
    (*itr)->StartSending(data);
  }
}

void LocalTcpTransport::InsertConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&LocalTcpTransport::DoInsertConnection,
                             shared_from_this(), connection));
}

void LocalTcpTransport::DoInsertConnection(ConnectionPtr connection) {
  connections_.insert(connection);
}

void LocalTcpTransport::RemoveConnection(ConnectionPtr connection) {
  strand_.dispatch(std::bind(&LocalTcpTransport::DoRemoveConnection,
                             shared_from_this(), connection));
}

void LocalTcpTransport::DoRemoveConnection(ConnectionPtr connection) {
  connections_.erase(connection);
}

}  // namespace priv

}  // namespace maidsafe
