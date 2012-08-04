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

#ifndef MAIDSAFE_PRIVATE_TCP_TRANSPORT_H_
#define MAIDSAFE_PRIVATE_TCP_TRANSPORT_H_

#include <memory>
#include <set>
#include <string>
#include <vector>
#include "boost/asio/io_service.hpp"
#include "boost/asio/strand.hpp"
#include "boost/asio/ip/tcp.hpp"
#include "maidsafe/private/transport.h"


namespace maidsafe {

namespace priv {

class TcpConnection;
class MessageHandler;

#ifdef __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Weffc++"
#endif
class TcpTransport : public Transport,
                     public std::enable_shared_from_this<TcpTransport> {
#ifdef __GNUC__
#pragma GCC diagnostic pop
#endif
 public:
  explicit TcpTransport(boost::asio::io_service &asio_service); // NOLINT
  virtual ~TcpTransport();
  virtual TransportCondition StartListening(const Endpoint &endpoint);
  virtual TransportCondition Bootstrap(const std::vector<Contact> &candidates);
  virtual void StopListening();
  virtual void Send(const std::string &data,
                    const Endpoint &endpoint,
                    const Timeout &timeout);
  static DataSize kMaxTransportMessageSize() { return 67108864; }

 private:
  TcpTransport(const TcpTransport&);
  TcpTransport& operator=(const TcpTransport&);
  friend class TcpConnection;
  typedef std::shared_ptr<boost::asio::ip::tcp::acceptor> AcceptorPtr;
  typedef std::shared_ptr<TcpConnection> ConnectionPtr;
  typedef std::set<ConnectionPtr> ConnectionSet;
  static void CloseAcceptor(AcceptorPtr acceptor);
  void HandleAccept(AcceptorPtr acceptor, ConnectionPtr connection,
                    const boost::system::error_code &ec);

  void InsertConnection(ConnectionPtr connection);
  void DoInsertConnection(ConnectionPtr connection);
  void RemoveConnection(ConnectionPtr connection);
  void DoRemoveConnection(ConnectionPtr connection);

  AcceptorPtr acceptor_;

  // Because the connections can be in an idle initial state with no pending
  // async operations (after calling PrepareSend()), they are kept alive with
  // a shared_ptr in this map, as well as in the async operation handlers.
  ConnectionSet connections_;
  boost::asio::io_service::strand strand_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_TCP_TRANSPORT_H_
