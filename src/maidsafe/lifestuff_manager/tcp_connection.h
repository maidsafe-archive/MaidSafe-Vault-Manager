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

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_TCP_CONNECTION_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_TCP_CONNECTION_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/asio/strand.hpp"
#include "boost/date_time/posix_time/posix_time_duration.hpp"


namespace maidsafe {

namespace lifestuff_manager {

class LocalTcpTransport;

class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
 public:
  explicit TcpConnection(const std::shared_ptr<LocalTcpTransport>& local_tcp_transport);
  ~TcpConnection() {}

  int Connect(const uint16_t& remote_port);
  void Close();
  void StartReceiving();
  void StartSending(const std::string& data);

  boost::asio::ip::tcp::socket &Socket() { return socket_; }

 private:
  TcpConnection(const TcpConnection&);
  TcpConnection &operator=(const TcpConnection&);

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

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_TCP_CONNECTION_H_
