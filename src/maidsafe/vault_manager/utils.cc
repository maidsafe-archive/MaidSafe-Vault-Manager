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

#include "maidsafe/vault_manager/utils.h"

//#include <cstdint>
//#include <iterator>
#include <mutex>
//#include <set>
//
//#include "boost/tokenizer.hpp"
//
//#include "maidsafe/common/on_scope_exit.h"
//#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
//#include "maidsafe/common/utils.h"
//#include "maidsafe/passport/passport.h"
//
//#include "maidsafe/vault_manager/controller_messages.pb.h"
//#include "maidsafe/vault_manager/vault_manager.h"
//#include "maidsafe/vault_manager/process_manager.h"
//#include "maidsafe/vault_manager/vault_info.h"
//#include "maidsafe/vault_manager/vault_info.pb.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace {

const char kSeparator('_');

#ifdef TESTING
std::once_flag test_env_flag;
Port g_test_vault_manager_port(0);
fs::path g_test_env_root_dir, g_path_to_vault;
bool g_using_default_environment(true);
std::vector<boost::asio::ip::udp::endpoint> g_bootstrap_ips;
int g_identity_index(0);
#endif

}  // unnamed namespace

void ToProtobuf(crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
                const VaultInfo& vault_info, protobuf::VaultInfo* protobuf_vault_info) {
  protobuf_vault_info->set_pmid(
      passport::EncryptPmid(*vault_info.pmid, symm_key, symm_iv)->string());
  protobuf_vault_info->set_chunkstore_path(vault_info.chunkstore_path.string());
  if ((*vault_info.owner_name)->IsInitialised())
    protobuf_vault_info->set_owner_name((*vault_info.owner_name)->string());
  protobuf_vault_info->set_label(vault_info.label);
}

void FromProtobuf(crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
                  const protobuf::VaultInfo& protobuf_vault_info, VaultInfo& vault_info) {
  vault_info.pmid = make_unique<passport::Pmid>(passport::DecryptPmid(
      crypto::CipherText{ NonEmptyString{ protobuf_vault_info.pmid() } }, symm_key, symm_iv));
  vault_info.chunkstore_path = protobuf_vault_info.chunkstore_path();
  if (protobuf_vault_info.has_owner_name()) {
    vault_info.owner_name = maidsafe::make_unique<passport::PublicMaid::Name>(
        Identity{ protobuf_vault_info.owner_name() });
  }
  vault_info.label = protobuf_vault_info.label();
}










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

//std::string GenerateVmidParameter(ProcessIndex process_index, Port vault_manager_port) {
//  return std::to_string(process_index) + kSeparator + std::to_string(vault_manager_port);
//}
//
//void ParseVmidParameter(const std::string& vault_manager_identifier,
//                        ProcessIndex& process_index, Port& vault_manager_port) {
//  on_scope_exit strong_guarantee([&vault_manager_port, &process_index] {
//    process_index = vault_manager_port = 0;
//  });
//
//  size_t separator_position(vault_manager_identifier.find(kSeparator));
//  if (separator_position == std::string::npos) {
//    LOG(kError) << "vault_manager_identifier " << vault_manager_identifier
//                << " has wrong format";
//    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
//  }
//  try {
//    process_index = static_cast<ProcessIndex>(
//        std::stoul(vault_manager_identifier.substr(0, separator_position)));
//    vault_manager_port =
//        static_cast<Port>(std::stoi(vault_manager_identifier.substr(separator_position + 1)));
//  }
//  catch (const std::logic_error& exception) {
//    LOG(kError) << "vault_manager_identifier " << vault_manager_identifier
//                << " has wrong format: " << exception.what();
//    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
//  }
//
//  if (process_index == 0) {
//    LOG(kError) << "Invalid process index of 0";
//    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
//  }
//
//#ifndef TESTING
//  if (vault_manager_port < VaultManager::kDefaultPort() ||
//      vault_manager_port >
//          VaultManager::kDefaultPort() + VaultManager::kMaxRangeAboveDefaultPort()) {
//    LOG(kError) << "Invalid Vaults Manager port " << vault_manager_port;
//  }
//#endif
//  strong_guarantee.Release();
//}

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
void SetTestEnvironmentVariables(Port test_vault_manager_port, fs::path test_env_root_dir,
                                 fs::path path_to_vault,
                                 std::vector<boost::asio::ip::udp::endpoint> bootstrap_ips) {
  std::call_once(test_env_flag,
                 [test_vault_manager_port, test_env_root_dir, path_to_vault, bootstrap_ips] {
    g_test_vault_manager_port = test_vault_manager_port;
    g_test_env_root_dir = test_env_root_dir;
    g_path_to_vault = path_to_vault;
    g_bootstrap_ips = bootstrap_ips;
    g_using_default_environment = false;
  });
}

Port GetTestVaultManagerPort() { return g_test_vault_manager_port; }
fs::path GetTestEnvironmentRootDir() { return g_test_env_root_dir; }
fs::path GetPathToVault() { return g_path_to_vault; }
std::vector<boost::asio::ip::udp::endpoint> GetBootstrapIps() { return g_bootstrap_ips; }
void SetIdentityIndex(int identity_index) { g_identity_index = identity_index; }
int IdentityIndex() { return g_identity_index; }
bool UsingDefaultEnvironment() { return g_using_default_environment; }
#endif  // TESTING

}  //  namespace vault_manager

}  //  namespace maidsafe
