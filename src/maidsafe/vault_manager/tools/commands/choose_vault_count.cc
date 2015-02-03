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

#include "maidsafe/vault_manager/tools/commands/choose_vault_count.h"

#include <limits>
#include <string>

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/vault_manager/vault_manager.h"
#include "maidsafe/vault_manager/tools/actions/connect_to_network.h"
#include "maidsafe/vault_manager/tools/actions/start_network.h"
#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/commands/choose_test.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

namespace {

std::string Instruction(bool new_network) {
  std::string instruction{"\nThis must be at least "};
  instruction += std::to_string(new_network ? GetDefault().kVaultCountNewNetwork : 1);
  instruction +=
      ".\nThere is no upper limit, but more than 20 on one PC will probably\n"
      "cause noticeable performance slowdown.  'Enter' to use default \"" +
      std::to_string(new_network ? GetDefault().kVaultCountNewNetwork : GetDefault().kVaultCount) +
      "\".\n";
  return instruction;
}

}  // anonymous namespace

ChooseVaultCount::ChooseVaultCount(LocalNetworkController* local_network_controller)
    : Command(local_network_controller, "Number of Vaults to start.",
              Instruction(local_network_controller->new_network) + kPrompt_) {}

void ChooseVaultCount::GetChoice() {
  TLOG(kDefaultColour) << kInstructions_;
  if (local_network_controller_->new_network) {
    while (!DoGetChoice(local_network_controller_->vault_count, &GetDefault().kVaultCountNewNetwork,
                        GetDefault().kVaultCountNewNetwork, std::numeric_limits<int>::max())) {
      TLOG(kDefaultColour) << '\n' << kInstructions_;
    }
  } else {
    while (!DoGetChoice(local_network_controller_->vault_count, &GetDefault().kVaultCount, 1,
                        std::numeric_limits<int>::max())) {
      TLOG(kDefaultColour) << '\n' << kInstructions_;
    }
  }
}

void ChooseVaultCount::HandleChoice() {
  if (local_network_controller_->new_network) {
    StartNetwork(local_network_controller_);
  } else {
    ConnectToNetwork(local_network_controller_);
  }
  local_network_controller_->current_command =
      maidsafe::make_unique<ChooseTest>(local_network_controller_);
  TLOG(kDefaultColour) << kSeparator_;
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
