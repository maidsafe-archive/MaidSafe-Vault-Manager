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

#ifndef MAIDSAFE_PRIVATE_MESSAGE_HANDLER_H_
#define MAIDSAFE_PRIVATE_MESSAGE_HANDLER_H_

#include <memory>
#include <string>

#include "boost/signals2/signal.hpp"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/private/transport.h"


namespace bs2 = boost::signals2;
typedef std::shared_ptr<maidsafe::rsa::PrivateKey> PrivateKeyPtr;
typedef maidsafe::rsa::PublicKey PublicKey;

namespace maidsafe {

typedef char SecurityType;
const SecurityType kNone(0x0);
const SecurityType kSign(0x1);
const SecurityType kSignWithParameters(0x2);
const SecurityType kAsymmetricEncrypt(0x4);
const SecurityType kSignAndAsymEncrypt(0x5);

namespace priv {

enum MessageType {
  kManagedEndpointMessage = 1,
  kNatDetectionRequest,
  kNatDetectionResponse,
  kProxyConnectRequest,
  kProxyConnectResponse,
  kForwardRendezvousRequest,
  kForwardRendezvousResponse,
  kRendezvousRequest,
  kRendezvousAcknowledgement
};

namespace protobuf {
class Endpoint;
class WrapperMessage;
}  // namespace protobuf

namespace test {
class TransportMessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;
class RudpMessageHandlerTest_BEH_MakeSerialisedWrapperMessage_Test;
}  // namespace test

// Highest possible message type ID, use as offset for type extensions.
const int kMaxMessageType(1000);

class MessageHandler {
 public:
  typedef std::shared_ptr<bs2::signal<void(const TransportCondition&,
                                           const Endpoint&)>>
          ErrorSigPtr;

  MessageHandler() : on_error_(new ErrorSigPtr::element_type),
                     callback_() {}
  ~MessageHandler() {}

  void OnMessageReceived(const std::string &request,
                         const Info &info,
                         std::string * /*response*/,
                         Timeout * /*timeout*/);
  void OnError(const TransportCondition &transport_condition,
               const Endpoint &remote_endpoint);

  void SetCallback(boost::function<void(const int&, const std::string&,
                                        const Info&, std::string*)> callback);
  ErrorSigPtr on_error() { return on_error_; }

  std::string MakeSerialisedWrapperMessage(const int &message_type, const std::string &payload);

 protected:
  void ProcessSerialisedMessage(const int &message_type,
                                        const std::string &payload,
                                        const SecurityType &security_type,
                                        const std::string &message_signature,
                                        const Info &info,
                                        std::string *message_response,
                                        Timeout *timeout);

 private:
  MessageHandler(const MessageHandler&);
  MessageHandler& operator=(const MessageHandler&);
  ErrorSigPtr on_error_;
  boost::function<void(const int&, const std::string&, const Info&, std::string*)> callback_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_MESSAGE_HANDLER_H_
