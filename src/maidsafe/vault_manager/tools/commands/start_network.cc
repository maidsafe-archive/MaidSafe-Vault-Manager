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

#include "maidsafe/vault_manager/tools/commands/start_network.h"

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/process.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/client_interface.h"
#include "maidsafe/vault_manager/vault_manager.h"
#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/commands/choose_test.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

StartNetwork::StartNetwork(LocalNetworkController* local_network_controller)
    : Command(local_network_controller, "Start Network"),
      test_env_root_dir_(),
      path_to_vault_(),
      vault_manager_port_(0),
      vault_count_(0),
      kDefaultTestEnvRootDir_(fs::temp_directory_path() / "MaidSafe_TestNetwork"),
      kDefaultPathToVault_(process::GetOtherExecutablePath(fs::path{ "vault" })),
      kDefaultVaultManagerPort_(44444),
      kDefaultVaultCount_(12) {}

void StartNetwork::PrintOptions() const {
  boost::system::error_code ec;
  if (test_env_root_dir_.empty()) {
    TLOG(kDefaultColour)
        << "Enter VaultManager root directory.  Hit enter to use default\n"
        << kDefaultTestEnvRootDir_ << '\n' << kDefaultOutput_;
  } else if (!fs::exists(test_env_root_dir_, ec) || ec) {
    TLOG(kDefaultColour)
        << "Do you wish to create " << test_env_root_dir_ << "?\nEnter 'y' or 'n'.\n"
        << kDefaultOutput_;
  } else if (path_to_vault_.empty()) {
    TLOG(kDefaultColour)
        << "Enter path to Vault executable.  Hit enter to use default\n"
        << kDefaultPathToVault_ << '\n' << kDefaultOutput_;
  } else if (vault_manager_port_ == 0) {
    TLOG(kDefaultColour)
        << "Enter preferred VaultManager listening port.  This should be between\n"
        << "1025 and 65536 inclusive.  Hit enter to use default " << kDefaultVaultManagerPort_
        << '\n' << kDefaultOutput_;
  } else {
    TLOG(kDefaultColour)
        << "Enter number of Vaults to start.  This must be at least 10.\nThere is no "
        << "upper limit, but more than 20 on one PC will probably\ncause noticeable "
        << "performance slowdown.  Hit enter to use default " << kDefaultVaultCount_ << '\n'
        << kDefaultOutput_;
  }
}

void StartNetwork::GetChoice() {
  for (;;) {
    while (!GetPathChoice(test_env_root_dir_, &kDefaultTestEnvRootDir_, false)) {
      TLOG(kDefaultColour) << '\n';
      PrintOptions();
    }
    boost::system::error_code ec;
    if (fs::exists(test_env_root_dir_, ec))
      break;

    PrintOptions();
    bool create;
    while (!GetBoolChoice(create, nullptr)) {
      TLOG(kDefaultColour) << '\n';
      PrintOptions();
    }
    if (create) {
      if (fs::create_directories(test_env_root_dir_, ec))
        break;
    }
  }

  PrintOptions();
  while (!GetPathChoice(path_to_vault_, &kDefaultPathToVault_, true)) {
    TLOG(kDefaultColour) << '\n';
    PrintOptions();
  }

  PrintOptions();
  while (!GetIntChoice(vault_manager_port_, &kDefaultVaultManagerPort_, 1025, 65536)) {
    TLOG(kDefaultColour) << '\n';
    PrintOptions();
  }

  PrintOptions();
  while (!GetIntChoice(vault_count_, &kDefaultVaultCount_, 10)) {
    TLOG(kDefaultColour) << '\n';
    PrintOptions();
  }
}

void StartNetwork::HandleChoice() {
  if (exit_) {
    local_network_controller_->current_command.reset();
    return;
  }




  routing::BootstrapContact bootstrap_contact{ maidsafe::GetLocalIp(),
                                               maidsafe::test::GetRandomPort() };
  ClientInterface::SetTestEnvironment(static_cast<Port>(vault_manager_port_), test_env_root_dir_,
                                      path_to_vault_, bootstrap_contact, vault_count_);
  TLOG(kRed) << "Not implemented yet.\n";
  TLOG(kGreen) << "Chose " << test_env_root_dir_ << '\n';
  TLOG(kGreen) << "Chose " << path_to_vault_ << '\n';
  TLOG(kGreen) << "Chose " << vault_manager_port_ << '\n';
  TLOG(kGreen) << "Chose " << vault_count_ << '\n';
  local_network_controller_->current_command =
      maidsafe::make_unique<ChooseTest>(local_network_controller_);
}

}  // namepsace tools

}  // namespace vault_manager

}  // namespace maidsafe
