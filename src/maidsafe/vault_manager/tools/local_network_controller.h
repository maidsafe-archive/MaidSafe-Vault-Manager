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

#ifndef MAIDSAFE_VAULT_MANAGER_TOOLS_LOCAL_NETWORK_CONTROLLER_H_
#define MAIDSAFE_VAULT_MANAGER_TOOLS_LOCAL_NETWORK_CONTROLLER_H_

#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/client_interface.h"
#include "maidsafe/vault_manager/vault_manager.h"

namespace maidsafe {

namespace vault_manager {

namespace tools {

class Command;

struct LocalNetworkController {
  explicit LocalNetworkController(const boost::filesystem::path& script_path);
  ~LocalNetworkController();
  std::deque<std::string> script_commands;
  std::vector<std::string> entered_commands;
  std::unique_ptr<Command> current_command;
  std::unique_ptr<ClientInterface> client_interface;
  std::unique_ptr<VaultManager> vault_manager;
};

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_TOOLS_LOCAL_NETWORK_CONTROLLER_H_
