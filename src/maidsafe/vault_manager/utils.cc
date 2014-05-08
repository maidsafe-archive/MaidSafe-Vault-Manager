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

#include "maidsafe/vault_manager/utils.h"

#include <algorithm>
#include <iterator>
#include <limits>
#include <mutex>

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/interprocess_messages.pb.h"
#include "maidsafe/vault_manager/vault_info.pb.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace {

#ifdef TESTING
std::once_flag test_env_flag;
Port g_test_vault_manager_port(0);
fs::path g_test_env_root_dir, g_path_to_vault;
bool g_using_default_environment(true);
routing::BootstrapContacts g_bootstrap_contacts;
int g_identity_index(0);
#endif

}  // unnamed namespace

void ToProtobuf(crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
                const VaultInfo& vault_info, protobuf::VaultInfo* protobuf_vault_info) {
  protobuf_vault_info->set_pmid(
      passport::EncryptPmid(*vault_info.pmid, symm_key, symm_iv)->string());
  protobuf_vault_info->set_chunkstore_path(vault_info.chunkstore_path.string());
  if (vault_info.max_disk_usage != 0U)
    protobuf_vault_info->set_max_disk_usage(vault_info.max_disk_usage.data);
  if (vault_info.owner_name->IsInitialised())
    protobuf_vault_info->set_owner_name(vault_info.owner_name->string());
  protobuf_vault_info->set_label(vault_info.label);
}

void FromProtobuf(crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
                  const protobuf::VaultInfo& protobuf_vault_info, VaultInfo& vault_info) {
  vault_info.pmid = make_unique<passport::Pmid>(passport::DecryptPmid(
      crypto::CipherText{ NonEmptyString{ protobuf_vault_info.pmid() } }, symm_key, symm_iv));
  vault_info.chunkstore_path = protobuf_vault_info.chunkstore_path();
  if (protobuf_vault_info.has_max_disk_usage())
    vault_info.max_disk_usage = DiskUsage{ protobuf_vault_info.max_disk_usage() };
  if (protobuf_vault_info.has_owner_name()) {
    vault_info.owner_name =
        passport::PublicMaid::Name{ Identity{ protobuf_vault_info.owner_name() } };
  }
  vault_info.label = protobuf_vault_info.label();
}

void SetExecutablePath(const boost::filesystem::path& executable_path, VaultInfo& vault_info) {
  boost::system::error_code ec;
  if (!fs::exists(executable_path, ec) || ec) {
    LOG(kError) << executable_path << " doesn't exist.  " << (ec ? ec.message() : "");
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  if (!fs::is_regular_file(executable_path, ec) || ec) {
    LOG(kError) << executable_path << " is not a regular file.  " << (ec ? ec.message() : "");
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  if (fs::is_symlink(executable_path, ec) || ec) {
    LOG(kError) << executable_path << " is a symlink.  " << (ec ? ec.message() : "");
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  LOG(kVerbose) << "Vault executable found at " << executable_path;
  vault_info.process_args.push_back(executable_path.string());
  // Executable path must be the first argument
  if (vault_info.process_args.size() > 1U)
    std::iter_swap(std::begin(vault_info.process_args), --std::end(vault_info.process_args));
}

std::string WrapMessage(MessageAndType message_and_type) {
  protobuf::WrapperMessage wrapper_message;
  wrapper_message.set_payload(message_and_type.first);
  wrapper_message.set_type(static_cast<int32_t>(message_and_type.second));
  return wrapper_message.SerializeAsString();
}

MessageAndType UnwrapMessage(std::string wrapped_message) {
  protobuf::WrapperMessage wrapper;
  if (!wrapper.ParseFromString(wrapped_message)) {
    LOG(kError) << "Failed to unwrap message";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
  }

  return std::make_pair(wrapper.payload(), static_cast<MessageType>(wrapper.type()));
}

#ifdef TESTING
void SetTestEnvironmentVariables(Port test_vault_manager_port, const fs::path& test_env_root_dir,
                                 const fs::path& path_to_vault,
                                 routing::BootstrapContacts bootstrap_contacts) {
  std::call_once(test_env_flag, [=] {
    g_test_vault_manager_port = test_vault_manager_port;
    g_test_env_root_dir = test_env_root_dir;
    g_path_to_vault = path_to_vault;
    g_bootstrap_contacts = bootstrap_contacts;
    g_using_default_environment = false;
  });
}

Port GetTestVaultManagerPort() { return g_test_vault_manager_port; }
fs::path GetTestEnvironmentRootDir() { return g_test_env_root_dir; }
fs::path GetPathToVault() { return g_path_to_vault; }
routing::BootstrapContacts GetBootstrapContacts() { return g_bootstrap_contacts; }
void SetIdentityIndex(int identity_index) { g_identity_index = identity_index; }
int IdentityIndex() { return g_identity_index; }
bool UsingDefaultEnvironment() { return g_using_default_environment; }
#endif  // TESTING

}  //  namespace vault_manager

}  //  namespace maidsafe
