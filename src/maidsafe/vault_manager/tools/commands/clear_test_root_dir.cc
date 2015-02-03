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

#include "maidsafe/vault_manager/tools/commands/clear_test_root_dir.h"
#include <string>

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/commands/choose_path_to_vault.h"
#include "maidsafe/vault_manager/tools/commands/choose_test_root_dir.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

ClearTestRootDir::ClearTestRootDir(LocalNetworkController* local_network_controller)
    : Command(local_network_controller, "Clear VaultManager root directory.",
              "  Do you wish to remove all contents of \n\"" +
                  local_network_controller->test_env_root_dir.string() + "\"?\n" +
                  "[y/n].  'Enter' to use default \"" +
                  (GetDefault().kClearTestRootDir ? "y" : "n") + "\".\n" + kPrompt_),
      clear_(false) {}

void ClearTestRootDir::GetChoice() {
  TLOG(kDefaultColour) << kInstructions_;
  while (!DoGetChoice(clear_, &GetDefault().kClearTestRootDir))
    TLOG(kDefaultColour) << '\n' << kInstructions_;
}

void ClearTestRootDir::HandleChoice() {
  if (clear_) {
    fs::remove_all(local_network_controller_->test_env_root_dir);
    fs::create_directories(local_network_controller_->test_env_root_dir);
    local_network_controller_->current_command =
        maidsafe::make_unique<ChoosePathToVault>(local_network_controller_);
  } else {
    local_network_controller_->current_command =
        maidsafe::make_unique<ChooseTestRootDir>(local_network_controller_);
  }
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
