/*  Copyright 2012 MaidSafe.net limited

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

#include "maidsafe/client_manager/utils.h"

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

#include "maidsafe/client_manager/controller_messages.pb.h"
#include "maidsafe/client_manager/client_manager.h"
#include "maidsafe/client_manager/local_tcp_transport.h"
#include "maidsafe/client_manager/process_manager.h"
#include "maidsafe/client_manager/return_codes.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace client_manager {

namespace detail {

namespace {

const char kSeparator('_');

#ifdef TESTING
std::once_flag test_env_flag;
Port g_test_client_manager_port(0);
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

bool UnwrapMessage(const std::string& wrapped_message, MessageType& message_type,
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

std::string GenerateVmidParameter(ProcessIndex process_index, Port client_manager_port) {
  return std::to_string(process_index) + kSeparator + std::to_string(client_manager_port);
}

void ParseVmidParameter(const std::string& client_manager_identifier,
                        ProcessIndex& process_index, Port& client_manager_port) {
  on_scope_exit strong_guarantee([&client_manager_port, &process_index] {
    process_index = client_manager_port = 0;
  });

  size_t separator_position(client_manager_identifier.find(kSeparator));
  if (separator_position == std::string::npos) {
    LOG(kError) << "client_manager_identifier " << client_manager_identifier
                << " has wrong format";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  try {
    process_index = static_cast<ProcessIndex>(
        std::stoul(client_manager_identifier.substr(0, separator_position)));
    client_manager_port =
        static_cast<Port>(std::stoi(client_manager_identifier.substr(separator_position + 1)));
  }
  catch (const std::logic_error& exception) {
    LOG(kError) << "client_manager_identifier " << client_manager_identifier
                << " has wrong format: " << exception.what();
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }

  if (process_index == 0) {
    LOG(kError) << "Invalid process index of 0";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }

#ifndef TESTING
  if (client_manager_port < ClientManager::kDefaultPort() ||
      client_manager_port >
          ClientManager::kDefaultPort() + ClientManager::kMaxRangeAboveDefaultPort()) {
    LOG(kError) << "Invalid Vaults Manager port " << client_manager_port;
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
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }

  transport->on_message_received().connect(on_message_received_slot);
  transport->on_error().connect([](const int & err) {
    LOG(kError) << "Transport error: " << err;
  });  // NOLINT (Fraser)
}

#ifdef TESTING
void SetTestEnvironmentVariables(Port test_client_manager_port, fs::path test_env_root_dir,
                                 fs::path path_to_vault,
                                 std::vector<boost::asio::ip::udp::endpoint> bootstrap_ips) {
  std::call_once(test_env_flag,
                 [test_client_manager_port, test_env_root_dir, path_to_vault, bootstrap_ips] {
    g_test_client_manager_port = test_client_manager_port;
    g_test_env_root_dir = test_env_root_dir;
    g_path_to_vault = path_to_vault;
    g_bootstrap_ips = bootstrap_ips;
    g_using_default_environment = false;
  });
}

Port GetTestClientManagerPort() { return g_test_client_manager_port; }
fs::path GetTestEnvironmentRootDir() { return g_test_env_root_dir; }
fs::path GetPathToVault() { return g_path_to_vault; }
std::vector<boost::asio::ip::udp::endpoint> GetBootstrapIps() { return g_bootstrap_ips; }
void SetIdentityIndex(int identity_index) { g_identity_index = identity_index; }
int IdentityIndex() { return g_identity_index; }
bool UsingDefaultEnvironment() { return g_using_default_environment; }
#endif  // TESTING

}  // namespace detail

}  //  namespace client_manager

}  //  namespace maidsafe
