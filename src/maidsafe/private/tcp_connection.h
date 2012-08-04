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

#ifndef MAIDSAFE_PRIVATE_TCP_CONNECTION_H_
#define MAIDSAFE_PRIVATE_TCP_CONNECTION_H_

#include <memory>
#include <string>
#include <vector>
#include "boost/asio/deadline_timer.hpp"
#include "boost/asio/io_service.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "boost/asio/strand.hpp"
#include "maidsafe/private/transport.h"

namespace maidsafe {

namespace priv {

class TcpTransport;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif
class TcpConnection : public std::enable_shared_from_this<TcpConnection> {
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif

 public:
  TcpConnection(const std::shared_ptr<TcpTransport> &tcp_transport,
                const boost::asio::ip::tcp::endpoint &remote);
  ~TcpConnection();

  boost::asio::ip::tcp::socket &Socket();

  void Close();
  void StartReceiving();
  void StartSending(const std::string &data, const Timeout &timeout);

 private:
  TcpConnection(const TcpConnection&);
  TcpConnection &operator=(const TcpConnection&);

  void DoClose();
  void DoStartReceiving();
  void DoStartSending();

  void CheckTimeout(const boost::system::error_code &ec);

  void StartConnect();
  void HandleConnect(const boost::system::error_code &ec);

  void StartReadSize();
  void HandleReadSize(const boost::system::error_code &ec);

  void StartReadData();
  void HandleReadData(const boost::system::error_code &ec, size_t length);

  void StartWrite();
  void HandleWrite(const boost::system::error_code &ec);

  void DispatchMessage();
  void EncodeData(const std::string &data);
  void CloseOnError(const TransportCondition &error);

  std::weak_ptr<TcpTransport> transport_;
  boost::asio::io_service::strand strand_;
  boost::asio::ip::tcp::socket socket_;
  boost::asio::deadline_timer timer_;
  boost::posix_time::ptime response_deadline_;
  boost::asio::ip::tcp::endpoint remote_endpoint_;
  std::vector<unsigned char> size_buffer_, data_buffer_;
  size_t data_size_, data_received_;
  Timeout timeout_for_response_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_TCP_CONNECTION_H_
