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

struct Default {
  Default();
  const boost::filesystem::path kTestEnvRootDir;
  const boost::filesystem::path kPathToVault;
  const boost::filesystem::path kPathToBootstrap;
  const int kVaultManagerPort;
  const int kVaultCountNewNetwork;
  const int kVaultCount;
  const bool kCreateTestRootDir;
  const bool kClearTestRootDir;
};

const Default& GetDefault();

struct LocalNetworkController {
  explicit LocalNetworkController(const boost::filesystem::path& script_path);
  ~LocalNetworkController();
  std::deque<std::string> script_commands;
  std::vector<std::string> entered_commands;
  std::unique_ptr<Command> current_command;
  std::unique_ptr<ClientInterface> client_interface;
  std::unique_ptr<VaultManager> vault_manager;
  boost::filesystem::path test_env_root_dir, path_to_vault, path_to_bootstrap_file;
  int vault_manager_port, vault_count;
  bool new_network;  // fixme
};

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_TOOLS_LOCAL_NETWORK_CONTROLLER_H_
