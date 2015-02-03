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
#include <cctype>
#include <functional>
#include <iterator>
#include <limits>
#include <mutex>

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/serialisation/serialisation.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/vault_info.h"
#include "maidsafe/vault_manager/messages/challenge.h"
#include "maidsafe/vault_manager/messages/challenge_response.h"
#include "maidsafe/vault_manager/messages/log_message.h"
#include "maidsafe/vault_manager/messages/max_disk_usage_update.h"
#include "maidsafe/vault_manager/messages/start_vault_request.h"
#include "maidsafe/vault_manager/messages/take_ownership_request.h"
#include "maidsafe/vault_manager/messages/vault_running_response.h"
#include "maidsafe/vault_manager/messages/vault_started.h"
#include "maidsafe/vault_manager/messages/vault_started_response.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

#if !defined(_MSC_VER) || _MSC_VER >= 1900
const MessageTag Challenge::tag;
const MessageTag ChallengeResponse::tag;
const MessageTag LogMessage::tag;
const MessageTag MaxDiskUsageUpdate::tag;
const MessageTag StartVaultRequest::tag;
const MessageTag TakeOwnershipRequest::tag;
const MessageTag VaultRunningResponse::tag;
const MessageTag VaultStarted::tag;
const MessageTag VaultStartedResponse::tag;
#endif

namespace {

#ifdef TESTING
std::once_flag test_env_flag;
tcp::Port g_test_vault_manager_port(0);
fs::path g_test_env_root_dir, g_path_to_vault;
bool g_using_default_environment(true);
std::vector<passport::PmidAndSigner> g_pmids_and_signers;
std::vector<passport::PublicPmid> g_public_pmids;
#endif

}  // unnamed namespace


namespace detail {

std::unique_ptr<asymm::PlainText> GetValue(const Challenge& challenge) {
  return maidsafe::make_unique<asymm::PlainText>(std::move(challenge.plaintext));
}

std::unique_ptr<VaultConfig> GetValue(const VaultStartedResponse& vault_started_response) {
  auto vault_config = maidsafe::make_unique<VaultConfig>(*vault_started_response.pmid,
                                                         vault_started_response.vault_dir,
                                                         vault_started_response.max_disk_usage);
#ifdef USE_VLOGGING
  vault_config->vlog_session_id = vault_started_response.vlog_session_id;
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
  vault_config->send_hostname_to_visualiser_server =
      vault_started_response.send_hostname_to_visualiser_server;
#endif
#ifdef TESTING
  vault_config->test_config.public_pmid_list = vault_started_response.public_pmids;
#endif
  return vault_config;
}

}  // namespace detail

NonEmptyString GenerateLabel() {
  std::string label{RandomAlphaNumericString(4)};
  for (int i(0); i < 4; ++i)
    label += ("-" + RandomAlphaNumericString(4));
  std::transform(std::begin(label), std::end(label), std::begin(label),
                 std::ptr_fun<int, int>(std::toupper));
  return NonEmptyString{label};
}

tcp::Port GetInitialListeningPort() {
#ifdef TESTING
  return GetTestVaultManagerPort() == 0 ? kLivePort + 100 : GetTestVaultManagerPort();
#else
  return kLivePort;
#endif
}

#ifdef TESTING
namespace test {

void SetEnvironment(tcp::Port test_vault_manager_port, const fs::path& test_env_root_dir,
                    const fs::path& path_to_vault, int pmid_list_size) {
  std::call_once(test_env_flag, [=] {
    if (!fs::exists(test_env_root_dir) || !fs::is_directory(test_env_root_dir)) {
      LOG(kError) << test_env_root_dir << " doesn't exist or is not a directory.";
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::not_a_directory));
    }
    g_test_vault_manager_port = test_vault_manager_port;
    g_test_env_root_dir = test_env_root_dir;
    g_path_to_vault = path_to_vault;
    for (int i(0); i < pmid_list_size; ++i) {
      g_pmids_and_signers.emplace_back(passport::CreatePmidAndSigner());
      g_public_pmids.emplace_back(passport::PublicPmid{g_pmids_and_signers.back().first});
    }
    g_using_default_environment = false;
  });
}

}  // namespace test

tcp::Port GetTestVaultManagerPort() { return g_test_vault_manager_port; }
fs::path GetTestEnvironmentRootDir() { return g_test_env_root_dir; }
fs::path GetPathToVault() { return g_path_to_vault; }
passport::PmidAndSigner GetPmidAndSigner(int index) { return g_pmids_and_signers.at(index); }
std::vector<passport::PublicPmid> GetPublicPmids() { return g_public_pmids; }
#endif  // TESTING

}  //  namespace vault_manager

}  //  namespace maidsafe
