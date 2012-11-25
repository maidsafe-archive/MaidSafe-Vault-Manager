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
#include <mutex>
#include <set>

#include "boost/lexical_cast.hpp"
#include "boost/tokenizer.hpp"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/lifestuff_manager/controller_messages_pb.h"
#include "maidsafe/private/lifestuff_manager/lifestuff_manager.h"
#include "maidsafe/private/lifestuff_manager/local_tcp_transport.h"
#include "maidsafe/private/lifestuff_manager/process_manager.h"
#include "maidsafe/private/lifestuff_manager/return_codes.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace detail {

namespace {

const char kSeparator('_');

#ifdef TESTING
std::once_flag test_env_flag;
Port g_test_lifestuff_manager_port(0);
fs::path g_test_env_root_dir;
bool g_using_default_environment(true);
#endif

}  // unnamed namespace


std::string WrapMessage(const MessageType& message_type, const std::string& payload) {
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

#ifndef TESTING
  if (lifestuff_manager_port < LifeStuffManager::kDefaultPort() ||
      lifestuff_manager_port >
          LifeStuffManager::kDefaultPort() + LifeStuffManager::kMaxRangeAboveDefaultPort()) {
    LOG(kError) << "Invalid Vaults Manager port " << lifestuff_manager_port;
    return do_fail();
  }
#endif

  return true;
}

bool StartControllerListeningPort(std::shared_ptr<LocalTcpTransport> transport,
                                  OnMessageReceived::slot_type on_message_received_slot,
                                  Port& local_port) {
  int count(0), result(1);
  local_port = transport->StartListening(0, result);
  while (result != kSuccess && count++ < 10)
    local_port = transport->StartListening(0, result);

  if (result != kSuccess) {
    LOG(kError) << "Failed to start listening port.";
    return false;
  }

  transport->on_message_received().connect(on_message_received_slot);
  transport->on_error().connect([](const int& err) { LOG(kError) << "Transport error: " << err; });  // NOLINT (Fraser)

  return true;
}

#ifdef TESTING
void SetTestEnvironmentVariables(Port test_lifestuff_manager_port, fs::path test_env_root_dir) {
  std::call_once(test_env_flag, [test_lifestuff_manager_port, test_env_root_dir] {
    g_test_lifestuff_manager_port = test_lifestuff_manager_port;
    g_test_env_root_dir = test_env_root_dir;
    g_using_default_environment = false;
  });
}

Port GetTestLifeStuffManagerPort() {
  return g_test_lifestuff_manager_port;
}

fs::path GetTestEnvironmentRootDir() {
  return g_test_env_root_dir;
}

bool UsingDefaultEnvironment() {
  return g_using_default_environment;
}
#endif  // TESTING


}  // namespace detail

}  //  namespace lifestuff_manager

}  //  namespace priv

}  //  namespace maidsafe
