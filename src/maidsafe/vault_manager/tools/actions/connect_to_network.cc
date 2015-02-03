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

#include "maidsafe/vault_manager/tools/actions/start_network.h"

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/routing/tests/zero_state_helpers.h"

#include "maidsafe/vault_manager/client_interface.h"
#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/utils.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

namespace {

void StartVaults(LocalNetworkController* local_network_controller, DiskUsage max_usage) {
  for (int i(0); i < local_network_controller->vault_count; ++i) {
    TLOG(kDefaultColour) << "Starting vault " << i << '\n';
#ifdef USE_VLOGGING
    assert(local_network_controller->vlog_session_id);
    assert(local_network_controller->send_hostname_to_visualiser_server);
    local_network_controller->client_interface
        ->StartVault(boost::filesystem::path(), max_usage,
                     *local_network_controller->vlog_session_id,
                     *local_network_controller->send_hostname_to_visualiser_server)
        .get();
#else
    local_network_controller->client_interface->StartVault(boost::filesystem::path(), max_usage)
        .get();
#endif
    Sleep(std::chrono::milliseconds(500));
  }
}

}  // unnamed namespace

void ConnectToNetwork(LocalNetworkController* local_network_controller) {
  ClientInterface::SetTestEnvironment(
      static_cast<tcp::Port>(local_network_controller->vault_manager_port),
      local_network_controller->test_env_root_dir, local_network_controller->path_to_vault,
      local_network_controller->vault_count);

  auto space_info(fs::space(local_network_controller->test_env_root_dir));
  DiskUsage max_usage{(9 * space_info.available) / (10 * local_network_controller->vault_count)};

  maidsafe::test::PrepareBootstrapFile(local_network_controller->path_to_bootstrap_file);

  StartVaultManagerAndClientInterface(local_network_controller);
  StartVaults(local_network_controller, max_usage);

  local_network_controller->client_interface->MarkNetworkAsStable();

  TLOG(kDefaultColour) << "Started " << local_network_controller->vault_count << " Vaults\n";
  TLOG(kGreen)
      << "Started Vaults successfully.\n"
      << "To keep the Vault(s) alive or stay connected to VaultManager, do not exit this tool.\n";
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
