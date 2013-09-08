/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/lifestuff_manager/local_tcp_transport.h"

#include <functional>

#include "maidsafe/common/log.h"

#include "maidsafe/lifestuff_manager/return_codes.h"
#include "maidsafe/lifestuff_manager/tcp_connection.h"


namespace asio = boost::asio;
namespace bs = boost::system;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace lifestuff_manager {

LocalTcpTransport::LocalTcpTransport(boost::asio::io_service &asio_service) // NOLINT
    : asio_service_(asio_service),
      on_message_received_(),
      on_error_(),
      acceptor_(asio_service),
      connections_(),
      strand_(asio_service),
      mutex_(),
      cond_var_(),
      done_(false) {}

LocalTcpTransport::~LocalTcpTransport() {
  for (auto connection : connections_)
    connection->Close();
}

Port LocalTcpTransport::StartListening(Port port, int& result) {
  std::unique_lock<std::mutex> lock(mutex_);
  strand_.post(std::bind(&LocalTcpTransport::DoStartListening, shared_from_this(), port,
                             &result));
  cond_var_.wait(lock, [=]()->bool { return done_; });  // NOLINT
  done_ = false;
  boost::system::error_code error_code;
  return acceptor_.local_endpoint(error_code).port();
}

void LocalTcpTransport::DoStartListening(Port port, int* result) {
  std::lock_guard<std::mutex> lock(mutex_);
  if (acceptor_.is_open()) {
    LOG(kError) << "Already listening on port " << port;
    *result = kAlreadyStarted;
    done_ = true;
    cond_var_.notify_all();
    return;
  }

  ip::tcp::endpoint endpoint(ip::address_v4::loopback(), port);

  bs::error_code ec;
  acceptor_.open(endpoint.protocol(), ec);
  if (ec) {
    LOG(kError) << "Could not open the socket: " << ec.message();
    boost::system::error_code ec;
    acceptor_.close(ec);
    *result = kInvalidAddress;
    done_ = true;
    cond_var_.notify_all();
    return;
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
    boost::system::error_code ec;
    acceptor_.close(ec);
    *result = kSetOptionFailure;
    done_ = true;
    cond_var_.notify_all();
    return;
  }

  acceptor_.bind(endpoint, ec);
  if (ec) {
    LOG(kError) << "Could not bind socket to endpoint: " << ec.message();
    boost::system::error_code ec;
    acceptor_.close(ec);
    *result = kBindError;
    done_ = true;
    cond_var_.notify_all();
    return;
  }

  acceptor_.listen(asio::socket_base::max_connections, ec);
  if (ec) {
    LOG(kError) << "Could not start listening: " << ec.message();
    boost::system::error_code ec;
    acceptor_.close(ec);
    *result = kListenError;
    done_ = true;
    cond_var_.notify_all();
    return;
  }

  ConnectionPtr new_connection(new TcpConnection(shared_from_this()));

  // The connection object is kept alive in the acceptor handler until HandleAccept() is called.
  acceptor_.async_accept(new_connection->Socket(),
                         strand_.wrap(std::bind(&LocalTcpTransport::HandleAccept,
                                                shared_from_this(), std::ref(acceptor_),
                                                new_connection, args::_1)));
  *result = kSuccess;
  done_ = true;
  cond_var_.notify_all();
}

void LocalTcpTransport::StopListening() {
  strand_.dispatch([this] {
    boost::system::error_code ec;
    if (acceptor_.is_open())
      acceptor_.close(ec);
    if (ec.value() != 0)
      LOG(kError) << "Acceptor close error: " << ec.message();
  });
}

void LocalTcpTransport::HandleAccept(boost::asio::ip::tcp::acceptor& acceptor,
                                     ConnectionPtr connection,
                                     const bs::error_code& ec) {
  if (!acceptor.is_open())
    return connection->Close();

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

void LocalTcpTransport::Connect(Port server_port, int& result) {
  std::unique_lock<std::mutex> lock(mutex_);
  strand_.post(std::bind(&LocalTcpTransport::DoConnect, shared_from_this(), server_port,
                             &result));
  cond_var_.wait(lock, [=]()->bool { return done_; });  // NOLINT
  done_ = false;
}

void LocalTcpTransport::DoConnect(Port server_port, int* result) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (acceptor_.is_open())
    *result = kAlreadyStarted;
  ConnectionPtr connection(new TcpConnection(shared_from_this()));
  *result = connection->Connect(server_port);
  if (*result == kSuccess)
    InsertConnection(connection);
  done_ = true;
  cond_var_.notify_all();
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
                        [port](ConnectionPtr connection)->bool {
                          boost::system::error_code error_code;
                          return connection->Socket().remote_endpoint(error_code).port() == port;
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

}  // namespace lifestuff_manager

}  // namespace maidsafe
