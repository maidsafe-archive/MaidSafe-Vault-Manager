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

#include "maidsafe/lifestuff_manager/utils.h"

#include <cstdint>
#include <iterator>
#include <mutex>
#include <set>
#include <vector>

#include "boost/asio/ip/udp.hpp"
#include "boost/tokenizer.hpp"

#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff_manager/controller_messages.pb.h"
#include "maidsafe/lifestuff_manager/lifestuff_manager.h"
#include "maidsafe/lifestuff_manager/local_tcp_transport.h"
#include "maidsafe/lifestuff_manager/process_manager.h"
#include "maidsafe/lifestuff_manager/return_codes.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff_manager {

namespace detail {

namespace {

const char kSeparator('_');

#ifdef TESTING
std::once_flag test_env_flag;
Port g_test_lifestuff_manager_port(0);
fs::path g_test_env_root_dir, g_path_to_vault;
bool g_using_default_environment(true);
std::vector<boost::asio::ip::udp::endpoint> g_bootstrap_ips;
int g_identity_index(0);
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
  return std::to_string(process_index) + kSeparator + std::to_string(lifestuff_manager_port);
}

void ParseVmidParameter(const std::string& lifestuff_manager_identifier,
                        ProcessIndex& process_index,
                        Port& lifestuff_manager_port) {
  on_scope_exit strong_guarantee([&lifestuff_manager_port, &process_index] {
                                   process_index = lifestuff_manager_port = 0;
                                 });

  size_t separator_position(lifestuff_manager_identifier.find(kSeparator));
  if (separator_position == std::string::npos) {
    LOG(kError) << "lifestuff_manager_identifier " << lifestuff_manager_identifier
                << " has wrong format";
    ThrowError(CommonErrors::invalid_parameter);
  }
  try {
    process_index = static_cast<ProcessIndex>(std::stoul(
                        lifestuff_manager_identifier.substr(0, separator_position)));
    lifestuff_manager_port =
        static_cast<Port>(std::stoi(lifestuff_manager_identifier.substr(separator_position + 1)));
  }
  catch(const std::logic_error& exception) {
    LOG(kError) << "lifestuff_manager_identifier " << lifestuff_manager_identifier
                << " has wrong format: " << exception.what();
    ThrowError(CommonErrors::invalid_parameter);
  }

  if (process_index == 0) {
    LOG(kError) << "Invalid process index of 0";
    ThrowError(CommonErrors::invalid_parameter);
  }

#ifndef TESTING
  if (lifestuff_manager_port < LifeStuffManager::kDefaultPort() ||
      lifestuff_manager_port >
          LifeStuffManager::kDefaultPort() + LifeStuffManager::kMaxRangeAboveDefaultPort()) {
    LOG(kError) << "Invalid Vaults Manager port " << lifestuff_manager_port;
  }
#endif
  strong_guarantee.Release();
}

void StartControllerListeningPort(std::shared_ptr<LocalTcpTransport> transport,
                                  OnMessageReceived::slot_type on_message_received_slot,
                                  Port& local_port) {
  int count(0), result(1);
  local_port = transport->StartListening(0, result);
  while (result != kSuccess && count++ < 10)
    local_port = transport->StartListening(0, result);

  if (result != kSuccess) {
    LOG(kError) << "Failed to start listening port.";
    ThrowError(CommonErrors::invalid_parameter);
  }

  transport->on_message_received().connect(on_message_received_slot);
  transport->on_error().connect([](const int& err) { LOG(kError) << "Transport error: " << err; });  // NOLINT (Fraser)
}

#ifdef TESTING
void SetTestEnvironmentVariables(Port test_lifestuff_manager_port,
                                 fs::path test_env_root_dir,
                                 fs::path path_to_vault,
                                 std::vector<boost::asio::ip::udp::endpoint> bootstrap_ips) {
  std::call_once(test_env_flag,
                 [test_lifestuff_manager_port, test_env_root_dir, path_to_vault, bootstrap_ips] {
                   g_test_lifestuff_manager_port = test_lifestuff_manager_port;
                   g_test_env_root_dir = test_env_root_dir;
                   g_path_to_vault = path_to_vault;
                   g_bootstrap_ips = bootstrap_ips;
                   g_using_default_environment = false;
                 });
}

Port GetTestLifeStuffManagerPort() { return g_test_lifestuff_manager_port; }
fs::path GetTestEnvironmentRootDir() { return g_test_env_root_dir; }
fs::path GetPathToVault() { return g_path_to_vault; }
std::vector<boost::asio::ip::udp::endpoint> GetBootstrapIps() { return g_bootstrap_ips; }
void SetIdentityIndex(int identity_index) { g_identity_index = identity_index; }
int IdentityIndex() { return g_identity_index; }
bool UsingDefaultEnvironment() { return g_using_default_environment; }
#endif  // TESTING


}  // namespace detail

}  //  namespace lifestuff_manager

}  //  namespace maidsafe
