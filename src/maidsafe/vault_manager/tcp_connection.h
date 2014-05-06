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

#ifndef MAIDSAFE_VAULT_MANAGER_TCP_CONNECTION_H_
#define MAIDSAFE_VAULT_MANAGER_TCP_CONNECTION_H_

#include <array>
#include <cstdint>
#include <deque>
#include <string>
#include <vector>

#include "boost/asio/buffer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/strand.hpp"
#include "boost/asio/ip/tcp.hpp"

#include "maidsafe/common/error.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

class TcpListener;

class TcpConnection {
 public:
  typedef uint32_t DataSize;
  // Constructor used when accepting an incoming connection.
  explicit TcpConnection(boost::asio::io_service& io_service);
  // Constructor used to attempt to connect to 'remote_port' on loopback address.
  TcpConnection(boost::asio::io_service& io_service, MessageReceivedFunctor on_message_received,
                ConnectionClosedFunctor connection_closed_functor, uint16_t remote_port);

  // Only required for instances created using the first c'tor.  Should only be called once per
  // TcpConnection instance.
  void Start(MessageReceivedFunctor on_message_received,
             ConnectionClosedFunctor on_connection_closed);

  void Send(std::string data);

  static size_t MaxMessageSize() { return 1024 * 1024; }  // bytes

  friend class TcpListener;

 private:
  TcpConnection(const TcpConnection&) = delete;
  TcpConnection(TcpConnection&&) = delete;
  TcpConnection& operator=(TcpConnection) = delete;

  struct ReceivingMessage {
    std::array<char, 4> size_buffer;
    std::vector<char> data_buffer;
  };

  struct SendingMessage {
    std::array<char, 4> size_buffer;
    std::string data;
  };

  void Close();

  void ReadSize();
  void ReadData();

  void DoSend();
  SendingMessage EncodeData(std::string data) const;

  boost::asio::ip::tcp::socket socket_;
  MessageReceivedFunctor on_message_received_;
  ConnectionClosedFunctor on_connection_closed_;
  ReceivingMessage receiving_message_;
  std::deque<SendingMessage> send_queue_;
  boost::asio::io_service::strand strand_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_TCP_CONNECTION_H_
