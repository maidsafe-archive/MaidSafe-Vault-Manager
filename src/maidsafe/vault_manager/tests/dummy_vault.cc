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

#include <chrono>
#include <cstdint>
#include <future>

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/vault_config.h"
#include "maidsafe/vault_manager/vault_interface.h"

int main(int argc, char* argv[]) {
  using maidsafe::vault_manager::VaultConfig;
  bool connected_to_vault_manager{false}, should_hang{false};
  int exit_code{0};
  try {
    auto unuseds(maidsafe::log::Logging::Instance().Initialise(argc, argv));
    if (unuseds.size() != 2U)
      BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::invalid_parameter));
    uint16_t port{static_cast<uint16_t>(std::stoi(std::string{&unuseds[1][0]}))};
    maidsafe::vault_manager::VaultInterface vault_interface{port};
    connected_to_vault_manager = true;

    std::future<void> worker;
    VaultConfig config{vault_interface.GetConfiguration()};
    switch (config.test_config.test_type) {
      case VaultConfig::TestType::kNone:
        break;
      case VaultConfig::TestType::kKillConnection:
        worker = std::async(std::launch::async, [&] { vault_interface.KillConnection(); });
        break;
      case VaultConfig::TestType::kSendInvalidMessage:
        worker = std::async(std::launch::async, [&] { vault_interface.SendInvalidMessage(); });
        break;
      case VaultConfig::TestType::kStopProcess:
        worker = std::async(std::launch::async, [&] { vault_interface.StopProcess(); });
        break;
      case VaultConfig::TestType::kIgnoreStopRequest:
        should_hang = true;
        break;
      default:
        BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::invalid_parameter));
    }
    exit_code = vault_interface.WaitForExit();
    worker.get();
  } catch (const maidsafe::maidsafe_error& error) {
    if (connected_to_vault_manager)
      LOG(kError) << error.what();
    else
      LOG(kError) << "This is only designed to be invoked by VaultManager.";
    exit_code = maidsafe::ErrorToInt(error);
  } catch (const std::exception& e) {
    if (connected_to_vault_manager)
      LOG(kError) << e.what();
    else
      LOG(kError) << "This is only designed to be invoked by VaultManager.";
    exit_code =
        maidsafe::ErrorToInt(maidsafe::MakeError(maidsafe::CommonErrors::invalid_parameter));
  }
  if (should_hang)
    maidsafe::Sleep(std::chrono::hours(6));
  return exit_code;
}
