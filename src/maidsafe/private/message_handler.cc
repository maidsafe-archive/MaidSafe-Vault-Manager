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

#include "maidsafe/private/message_handler.h"

#include <string>

#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"

#include "maidsafe/private/controller_messages_pb.h"


namespace maidsafe {

namespace priv {

void MessageHandler::OnMessageReceived(const std::string &request,
                                       const Info &info,
                                       std::string *response,
                                       Timeout *timeout) {
  protobuf::WrapperMessage wrapper;
  *timeout = kImmediateTimeout;
  if (wrapper.ParseFromString(request) && wrapper.IsInitialized()) {
    callback_(wrapper.msg_type(), wrapper.payload(), info, response);
  } else {
    LOG(kError) << "OnMessageReceived: failed to parse message";
  }
}

void MessageHandler::OnError(const TransportCondition &transport_condition,
                             const Endpoint &remote_endpoint) {
  LOG(kError) << "OnError (" << transport_condition << ")";
  (*on_error_)(transport_condition, remote_endpoint);
}

void MessageHandler::ProcessSerialisedMessage(
    const int &/*message_type*/,
    const std::string &/*payload*/,
    const SecurityType &/*security_type*/,
    const std::string &/*message_signature*/,
    const Info & /*info*/,
    std::string* /*message_response*/,
    Timeout* /*timeout*/) {}

std::string MessageHandler::MakeSerialisedWrapperMessage(const int &message_type,
                                                         const std::string &payload) {
  protobuf::WrapperMessage wrapper_message;
  wrapper_message.set_msg_type(message_type);
  wrapper_message.set_payload(payload);
  return wrapper_message.SerializeAsString();
}

void MessageHandler::SetCallback(
    boost::function<void(const int&, const std::string&, const Info&, std::string*)> callback) {
  callback_ = callback;
}

}  //  namespace priv

}  //  namespace maidsafe
