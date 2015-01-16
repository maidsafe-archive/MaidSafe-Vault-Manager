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

#include <future>
#include <memory>
#include <string>
#include <vector>

#include "asio/steady_timer.hpp"
#include "asio/error.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/vault_config.h"


namespace maidsafe {

namespace vault_manager {

class LocalTcpTransport;
struct VaultInfo;
namespace protobuf { class VaultInfo; }

namespace detail {

template <typename T>
T Parse(const std::string& /*message*/) {
  return T::need_to_specialise;
}

template <>
std::unique_ptr<VaultConfig> Parse<std::unique_ptr<VaultConfig>>(
    const std::string& message);

template <>
std::unique_ptr<asymm::PlainText> Parse<std::unique_ptr<asymm::PlainText>>(
    const std::string& message);

template <>
std::unique_ptr<passport::PmidAndSigner> Parse<std::unique_ptr<passport::PmidAndSigner>>(
    const std::string& message);

}  // namespace detail



template <typename ProtobufMessage>
ProtobufMessage ParseProto(const std::string& serialised_message) {
  ProtobufMessage protobuf_message;
  if (!protobuf_message.ParseFromString(serialised_message))
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::parsing_error));
  return protobuf_message;
}

void ToProtobuf(crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
                const VaultInfo& vault_info, protobuf::VaultInfo* protobuf_vault_info);

void FromProtobuf(crypto::AES256Key symm_key, crypto::AES256InitialisationVector symm_iv,
                  const protobuf::VaultInfo& protobuf_vault_info, VaultInfo& vault_info);

std::string WrapMessage(MessageAndType message_and_type);

MessageAndType UnwrapMessage(std::string wrapped_message);

NonEmptyString GenerateLabel();

tcp::Port GetInitialListeningPort();

#ifdef TESTING
namespace test {

void SetEnvironment(tcp::Port test_vault_manager_port,
    const boost::filesystem::path& test_env_root_dir,
    const boost::filesystem::path& path_to_vault,
    int pmid_list_size = 0);

}  // namespace test

tcp::Port GetTestVaultManagerPort();
boost::filesystem::path GetTestEnvironmentRootDir();
boost::filesystem::path GetPathToVault();
passport::PmidAndSigner GetPmidAndSigner(int index);
std::vector<passport::PublicPmid> GetPublicPmids();
std::string GetSerialisedPublicPmids();
#endif

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_UTILS_H_
