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

#include "maidsafe/vault_manager/tools/commands/choose_test_root_dir.h"
#include <string>

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/commands/choose_path_to_vault.h"
#include "maidsafe/vault_manager/tools/commands/clear_test_root_dir.h"
#include "maidsafe/vault_manager/tools/commands/create_test_root_dir.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

namespace {

std::string GetTitle(bool new_network) {
  return new_network ? std::string("Start Network") : std::string("Connect to Network");
}
}

ChooseTestRootDir::ChooseTestRootDir(LocalNetworkController* local_network_controller)
    : Command(local_network_controller, "Path to VaultManager root directory.",
              "  'Enter' to use default\n\"" + GetDefault().kTestEnvRootDir.string() + "\"\n" +
                  kPrompt_,
              GetTitle(local_network_controller->new_network)) {}

void ChooseTestRootDir::GetChoice() {
  TLOG(kDefaultColour) << kInstructions_;
  while (!DoGetChoice(local_network_controller_->test_env_root_dir, &GetDefault().kTestEnvRootDir,
                      false)) {
    TLOG(kDefaultColour) << '\n' << kInstructions_;
  }
}

void ChooseTestRootDir::HandleChoice() {
  if (fs::exists(local_network_controller_->test_env_root_dir)) {
    if (fs::is_empty(local_network_controller_->test_env_root_dir)) {
      local_network_controller_->current_command =
          maidsafe::make_unique<ChoosePathToVault>(local_network_controller_);
    } else {
      local_network_controller_->current_command =
          maidsafe::make_unique<ClearTestRootDir>(local_network_controller_);
    }
  } else {
    local_network_controller_->current_command =
        maidsafe::make_unique<CreateTestRootDir>(local_network_controller_);
  }
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
