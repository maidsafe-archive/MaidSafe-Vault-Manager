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
#include "maidsafe/common/tcp/connection.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/vault_config.h"


namespace maidsafe {

namespace vault_manager {

struct Challenge;
struct VaultStartedResponse;

namespace detail {

std::unique_ptr<asymm::PlainText> GetValue(const Challenge& challenge);

std::unique_ptr<VaultConfig> GetValue(const VaultStartedResponse& vault_started_response);

}  // namespace detail

template <typename T>
void Send(tcp::ConnectionPtr connection, T message) {
  connection->Send(Serialise(T::tag, std::move(message)));
}

NonEmptyString GenerateLabel();

tcp::Port GetInitialListeningPort();

#ifdef TESTING
namespace test {

void SetEnvironment(tcp::Port test_vault_manager_port,
                    const boost::filesystem::path& test_env_root_dir,
                    const boost::filesystem::path& path_to_vault, int pmid_list_size = 0);

}  // namespace test

tcp::Port GetTestVaultManagerPort();
boost::filesystem::path GetTestEnvironmentRootDir();
boost::filesystem::path GetPathToVault();
passport::PmidAndSigner GetPmidAndSigner(int index);
std::vector<passport::PublicPmid> GetPublicPmids();
#endif

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_UTILS_H_
