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

#include "maidsafe/vault_manager/tcp_connection.h"

#include "boost/asio/error.hpp"
#include "boost/asio/read.hpp"
#include "boost/asio/write.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace asio = boost::asio;
namespace ip = asio::ip;
namespace args = std::placeholders;

namespace maidsafe {

namespace vault_manager {

TcpConnection::TcpConnection(boost::asio::io_service& io_service)
    : socket_(io_service),
      on_message_received_(),
      on_connection_closed_(),
      receiving_message_(),
      send_queue_(),
      strand_(io_service) {
  static_assert((sizeof(DataSize)) == 4, "DataSize must be 4 bytes.");
  assert(socket_.is_open());
}

TcpConnection::TcpConnection(boost::asio::io_service& io_service,
                             MessageReceivedFunctor on_message_received,
                             ConnectionClosedFunctor on_connection_closed, uint16_t remote_port)
    : socket_(io_service),
      on_message_received_(on_message_received),
      on_connection_closed_(on_connection_closed),
      receiving_message_(),
      send_queue_(),
      strand_(io_service) {
  try {
    socket_.connect(ip::tcp::endpoint(ip::address_v6::loopback(), remote_port));
    assert(socket_.is_open());
  }
  catch (const boost::system::system_error& error) {
    LOG(kError) << "Failed to connect to " << remote_port << ": " << error.what();
    throw;
  }
  strand_.dispatch([this] { ReadSize(); });
}

void TcpConnection::Start(MessageReceivedFunctor on_message_received,
                          ConnectionClosedFunctor on_connection_closed) {
  if (on_message_received_) {
    LOG(kError) << "Already started.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::already_initialised));
  }
  on_message_received_ = on_message_received;
  on_connection_closed_ = on_connection_closed;
  strand_.dispatch([this] { ReadSize(); });
}

void TcpConnection::Close() {
  strand_.dispatch([this] {
    boost::system::error_code ignored_ec;
    socket_.close(ignored_ec);
    on_connection_closed_();
  });
}

void TcpConnection::ReadSize() {
  asio::async_read(socket_, asio::buffer(receiving_message_.size_buffer),
                   [this](const boost::system::error_code& ec, size_t bytes_transferred) {
    if (ec) {
      //if (ec == asio::error::eof) {
      //  /*Sleep(std::chrono::milliseconds(10));*/
      //  return strand_.post(std::bind(&TcpConnection::ReadSize, shared_from_this()));
      //} else {
        if (ec != asio::error::connection_reset)
          LOG(kError) << ec.message();
        return Close();
      //}
    }
    assert(bytes_transferred == 4U);
    static_cast<void>(bytes_transferred);

    DataSize data_size;
    data_size = (((((receiving_message_.size_buffer[0] << 8) |
                     receiving_message_.size_buffer[1]) << 8) |
                     receiving_message_.size_buffer[2]) << 8) |
                     receiving_message_.size_buffer[3];
    if (data_size > MaxMessageSize()) {
      LOG(kError) << "Incoming message size of " << data_size
                  << " bytes exceeds maximum allowed of " << MaxMessageSize() << " bytes.";
      receiving_message_.data_buffer.clear();
      return Close();
    }

    receiving_message_.data_buffer.resize(data_size);
    ReadData();
  });
}

void TcpConnection::ReadData() {
  asio::async_read(socket_, asio::buffer(receiving_message_.data_buffer), strand_.wrap(
                   [this](const boost::system::error_code& ec, size_t bytes_transferred) {
    if (ec) {
      LOG(kError) << "Failed to read message body: " << ec.message();
      return Close();
    }
    assert(bytes_transferred == receiving_message_.data_buffer.size());
    static_cast<void>(bytes_transferred);

    // Dispatch the message outside the strand.
    std::string data{ std::begin(receiving_message_.data_buffer),
                      std::end(receiving_message_.data_buffer) };
    strand_.get_io_service().post([=] { on_message_received_(std::move(data)); });
    strand_.dispatch([this] { ReadSize(); });
  }));
}

void TcpConnection::Send(std::string data) {
  SendingMessage message{ EncodeData(std::move(data)) };
  strand_.post([this, message] {
    bool currently_sending{ !send_queue_.empty() };
    send_queue_.emplace_back(std::move(message));
    if (!currently_sending)
      DoSend();
  });
}

void TcpConnection::DoSend() {
  std::array<asio::const_buffer, 2> buffers;
  buffers[0] = asio::buffer(send_queue_.front().size_buffer);
  buffers[1] = asio::buffer(send_queue_.front().data.data(), send_queue_.front().data.size());
  asio::async_write(socket_, buffers, strand_.wrap(
                    [this](const boost::system::error_code& ec, size_t bytes_transferred) {
    if (ec) {
      LOG(kError) << "Failed to send message: " << ec.message();
      return Close();
    }
    assert(bytes_transferred == send_queue_.front().data.size());
    static_cast<void>(bytes_transferred);

    send_queue_.pop_front();
    if (!send_queue_.empty())
      DoSend();
  }));
}

TcpConnection::SendingMessage TcpConnection::EncodeData(std::string data) const {
  if (data.size() > MaxMessageSize())
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_string_size));

  SendingMessage message;
  for (int i = 0; i != 4; ++i)
    message.size_buffer[i] = static_cast<char>(data.size() >> (8 * (3 - i)));
  message.data = std::move(data);

  return message;
}

}  // namespace vault_manager

}  // namespace maidsafe
