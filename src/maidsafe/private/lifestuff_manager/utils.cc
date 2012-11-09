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

#include "maidsafe/private/lifestuff_manager/utils.h"

#include <cstdint>
#include <iterator>
#include <set>

#include "boost/lexical_cast.hpp"
#include "boost/tokenizer.hpp"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/lifestuff_manager/controller_messages_pb.h"
#include "maidsafe/private/lifestuff_manager/local_tcp_transport.h"
#include "maidsafe/private/lifestuff_manager/process_manager.h"
#include "maidsafe/private/lifestuff_manager/lifestuff_manager.h"


namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace detail {

namespace {

const char kSeparator('_');

}  // unnamed namespace

asymm::PublicKey kMaidSafePublicKey() {
  static auto const decoded_key = asymm::DecodeKey(asymm::EncodedPublicKey(DecodeFromHex("308201080282010100e97d80923586b7ac2c72b8087598af9bd054249879b8d99c249af05ae4338dcd969c440a39a79d8caba34a7bc5571e92557c1ede11d48ba34dc464b7f7f358092d391622a2a20c183d6f2969827e537e6dd650f7f17cfa9ca8b3e90b86212e0718855468286d353d0279e6cbdc70b338fa56362b15c7534e2ee1ff6271c8a98b09f7bab16c47576826aefa2485720c0bf30c28deb5d5eb583fdfb3b4182f4ba83b7b004d414bf7ae4c54402ed86064096ba2cec02fcaf3368c9b04700e5e7a55f2d16286ad890d7c39395a04ccd27f7302ff55ba5eea4f5ae9d81371db9bb32dcbecca9a1f96c6a58bd9b63e2bfcf89ecaf1b2b0d29e798892968d0f0057e177020111")));  // NOLINT
  return decoded_key;
}

std::string WrapMessage(const MessageType& message_type,
                        const std::string& payload) {
  protobuf::WrapperMessage wrapper_message;
  wrapper_message.set_type(static_cast<int>(message_type));
  wrapper_message.set_payload(payload);
  return wrapper_message.SerializeAsString();
}

bool UnwrapMessage(const std::string& wrapped_message,
                   MessageType& message_type,
                   std::string& payload) {
  protobuf::WrapperMessage wrapper;
  if (wrapper.ParseFromString(wrapped_message) && wrapper.IsInitialized()) {
    message_type = static_cast<MessageType>(wrapper.type());
    payload = wrapper.payload();
    return true;
  } else {
    LOG(kError) << "Failed to unwrap message";
    message_type = static_cast<MessageType>(0);
    payload.clear();
    return false;
  }
}

std::string GenerateVmidParameter(const ProcessIndex& process_index,
                                  const Port& lifestuff_manager_port) {
  return boost::lexical_cast<std::string>(process_index) + kSeparator +
         boost::lexical_cast<std::string>(lifestuff_manager_port);
}

bool ParseVmidParameter(const std::string& lifestuff_manager_identifier,
                        ProcessIndex& process_index,
                        Port& lifestuff_manager_port) {
  auto do_fail([&]()->bool {
    process_index = lifestuff_manager_port = 0;
    return false;
  });

  size_t separator_position(lifestuff_manager_identifier.find(kSeparator));
  if (separator_position == std::string::npos) {
    LOG(kError) << "lifestuff_manager_identifier " << lifestuff_manager_identifier
                << " has wrong format";
    return do_fail();
  }
  try {
    process_index = boost::lexical_cast<ProcessIndex>(
        lifestuff_manager_identifier.substr(0, separator_position));
    lifestuff_manager_port =
        boost::lexical_cast<Port>(lifestuff_manager_identifier.substr(separator_position + 1));
  }
  catch(const boost::bad_lexical_cast& exception) {
    LOG(kError) << "lifestuff_manager_identifier " << lifestuff_manager_identifier
                << " has wrong format: " << exception.what();
    return do_fail();
  }

  if (process_index == 0) {
    LOG(kError) << "Invalid process index of 0";
    return do_fail();
  }

  if (lifestuff_manager_port < LifeStuffManager::kMinPort() ||
      lifestuff_manager_port > LifeStuffManager::kMaxPort()) {
    LOG(kError) << "Invalid Vaults Manager port " << lifestuff_manager_port;
    return do_fail();
  }

  return true;
}

}  // namespace detail

}  //  namespace lifestuff_manager

}  //  namespace priv

}  //  namespace maidsafe
