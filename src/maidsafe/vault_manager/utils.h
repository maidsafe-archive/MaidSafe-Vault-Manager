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

#ifndef MAIDSAFE_VAULT_MANAGER_UTILS_H_
#define MAIDSAFE_VAULT_MANAGER_UTILS_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/asio/ip/udp.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/crypto.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

class LocalTcpTransport;
struct VaultInfo;
namespace protobuf { class VaultInfo; }

void ToProtobuf(crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
                const VaultInfo& vault_info, protobuf::VaultInfo* protobuf_vault_info);

void FromProtobuf(crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
                  const protobuf::VaultInfo& protobuf_vault_info, VaultInfo& vault_info);

void SetExecutablePath(const boost::filesystem::path& executable_path, VaultInfo& vault_info);

std::string WrapMessage(MessageAndType message_and_type);

MessageAndType UnwrapMessage(std::string wrapped_message);

#ifdef TESTING
void SetTestEnvironmentVariables(Port test_vault_manager_port,
                                 const boost::filesystem::path& test_env_root_dir,
                                 const boost::filesystem::path& path_to_vault,
                                 std::vector<boost::asio::ip::udp::endpoint> bootstrap_ips);
Port GetTestVaultManagerPort();
boost::filesystem::path GetTestEnvironmentRootDir();
boost::filesystem::path GetPathToVault();
std::vector<boost::asio::ip::udp::endpoint> GetBootstrapIps();
void SetIdentityIndex(int identity_index);
int IdentityIndex();
bool UsingDefaultEnvironment();
#endif

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_UTILS_H_
