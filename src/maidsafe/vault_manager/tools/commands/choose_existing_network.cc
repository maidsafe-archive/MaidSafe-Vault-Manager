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

#include "maidsafe/vault_manager/tools/commands/choose_existing_network.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/commands/choose_path_to_bootstrap.h"
#include "maidsafe/vault_manager/tools/commands/choose_test_root_dir.h"

namespace maidsafe {

namespace vault_manager {

namespace tools {

ChooseExistingNetwork::ChooseExistingNetwork(LocalNetworkController* local_network_controller)
    : Command(local_network_controller, "Choose Existing Network.",
              "  \n  1. Connect to MaidSafe Test Network. "
              "  \n  2. Connect to other network.\n" +
                  kPrompt_),
      choice_(0) {}

void ChooseExistingNetwork::GetChoice() {
  TLOG(kDefaultColour) << kInstructions_;
  while (!DoGetChoice(choice_, static_cast<int*>(nullptr), 1, 2))
    TLOG(kDefaultColour) << '\n' << kInstructions_;
}

void ChooseExistingNetwork::HandleChoice() {
  switch (choice_) {
    case 1:
      local_network_controller_->path_to_bootstrap_file = "none";
      local_network_controller_->current_command =
          maidsafe::make_unique<ChooseTestRootDir>(local_network_controller_);
      break;
    case 2:
      local_network_controller_->current_command =
          maidsafe::make_unique<ChoosePathToBootstrap>(local_network_controller_);
      break;
    default:
      assert(false);
  }
  TLOG(kDefaultColour) << kSeparator_;
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
