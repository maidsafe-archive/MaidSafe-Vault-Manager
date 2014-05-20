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

#include "maidsafe/vault_manager/tools/commands/begin.h"

#include "maidsafe/common/config.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/commands/connect_to_vault_manager.h"
#include "maidsafe/vault_manager/tools/commands/start_network.h"

namespace maidsafe {

namespace vault_manager {

namespace tools {

Begin::Begin(LocalNetworkController* local_network_controller)
    : Command(local_network_controller,
              "MaidSafe Local Network Controller " + kApplicationVersion() + ": Main Options"),
      choice_(0) {}

void Begin::PrintOptions() const {
  TLOG(kDefaultColour)
      << "\nPlease choose from the following options ('" << kQuitCommand_ << "' to quit):\n\n"
      << "  1. Start a new network on this machine.\n"
      << "  2. Connect to an existing VaultManager on this machine.\n" << kDefaultOutput_;
}

void Begin::GetChoice() {
  while (!GetIntChoice(choice_, nullptr, 1, 2)) {
    TLOG(kDefaultColour) << '\n';
    PrintOptions();
  }
}

void Begin::HandleChoice() {
  if (exit_) {
    local_network_controller_->current_command.reset();
  } else if (choice_ == 1) {
    local_network_controller_->current_command =
        maidsafe::make_unique<StartNetwork>(local_network_controller_);
  } else {
    local_network_controller_->current_command =
        maidsafe::make_unique<ConnectToVaultManager>(local_network_controller_);
  }
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
