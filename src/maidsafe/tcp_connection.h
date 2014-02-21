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

#ifndef MAIDSAFE_CLIENT_MANAGER_TCP_CONNECTION_H_
#define MAIDSAFE_CLIENT_MANAGER_TCP_CONNECTION_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/asio/strand.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"

namespace maidsafe {

namespace client_manager {

class LocalTcpTransport;

class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
 public:
  explicit TcpConnection(const std::shared_ptr<LocalTcpTransport>& local_tcp_transport);
  ~TcpConnection() {}

  int Connect(uint16_t remote_port);
  void Close();
  void StartReceiving();
  void StartSending(const std::string& data);

  boost::asio::ip::tcp::socket& Socket() { return socket_; }

 private:
  TcpConnection(const TcpConnection&);
  TcpConnection& operator=(const TcpConnection&);

  // Maximum number of bytes to read at a time
  static int32_t kMaxTransportChunkSize() { return 65536; }

  void DoClose();
  void DoStartReceiving();
  void DoStartSending();

  void StartReadSize();
  void HandleReadSize(const boost::system::error_code& ec);

  void StartReadData();
  void HandleReadData(const boost::system::error_code& ec, size_t length);

  void StartWrite();
  void HandleWrite(const boost::system::error_code& ec);

  void DispatchMessage();
  void EncodeData(const std::string& data);

  std::weak_ptr<LocalTcpTransport> transport_;
  boost::asio::io_service::strand strand_;
  boost::asio::ip::tcp::socket socket_;
  std::vector<unsigned char> size_buffer_, data_buffer_;
  size_t data_size_, data_received_;
};

}  // namespace client_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MANAGER_TCP_CONNECTION_H_
