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

#ifdef USE_VLOGGING

#include "maidsafe/vault_manager/tools/commands/choose_to_reveal_hostname.h"

#include "boost/asio/ip/host_name.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/commands/choose_vault_count.h"

namespace maidsafe {

namespace vault_manager {

namespace tools {

ChooseToRevealHostname::ChooseToRevealHostname(LocalNetworkController* local_network_controller)
    : Command(
          local_network_controller, "Choose to reveal hostname.",
          "  Do you wish to send your\nmachine's hostname (\"" + boost::asio::ip::host_name() +
              "\") to the visualiser\nwhere it can be publicly viewed?  We recommend you don't.\n" +
              "[y/n].  'Enter' to use default \"" +
              (GetDefault().kSendHostnameToVisualiserServer ? "y" : "n") + "\".\n" + kPrompt_) {}

void ChooseToRevealHostname::GetChoice() {
  TLOG(kDefaultColour) << kInstructions_;
  local_network_controller_->send_hostname_to_visualiser_server =
      maidsafe::make_unique<bool>(false);
  while (!DoGetChoice(*local_network_controller_->send_hostname_to_visualiser_server,
                      &GetDefault().kSendHostnameToVisualiserServer)) {
    TLOG(kDefaultColour) << '\n' << kInstructions_;
  }
}

void ChooseToRevealHostname::HandleChoice() {
  local_network_controller_->current_command =
      maidsafe::make_unique<ChooseVaultCount>(local_network_controller_);
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // defined USE_VLOGGING
