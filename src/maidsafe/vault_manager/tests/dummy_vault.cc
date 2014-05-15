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

#include "maidsafe/vault_manager/vault_interface.h"


namespace maidsafe {

namespace vault_manager {

namespace test {

void KillConnection(VaultInterface& vault_interface) {
  maidsafe::Sleep(std::chrono::seconds(1));
  vault_interface.tcp_connection_.reset();
}

void SendInvalidMessage(VaultInterface& vault_interface) {
  vault_interface.tcp_connection_->Send("Rubbish");
}

void StopProcess(VaultInterface& vault_interface) {
  maidsafe::Sleep(std::chrono::seconds(1));
  vault_interface.HandleVaultShutdownRequest();
}

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe

int main(int argc, char* argv[]) {
  using maidsafe::vault_manager::VaultInterface;
  try {
    auto unuseds(maidsafe::log::Logging::Instance().Initialise(argc, argv));
    if (unused_options.size() != 1U)
      BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::invalid_parameter));
    uint16_t port{ std::to_string(std::string{ &unused[0] }) };
    VaultInterface vault_interface{ port };

    std::future<void> worker;
    VaultInterface::Configuration config{ vault_interface.GetConfiguration() };
    switch (config.test_type) {
      case TestType::kKillConnection:
        worker = std::async{ std::launch::async, [&] { KillConnection(vault_interface); } };
        break;
      case TestType::kSendInvalidMessage:
        worker = std::async{ std::launch::async, [&] { SendInvalidMessage(vault_interface); } };
        break;
      case TestType::kStopProcess:
        worker = std::async{ std::launch::async, [&] { StopProcess(vault_interface); } };
        break;
      default:
        BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::invalid_parameter));
    }
    int result{ vault_interface.WaitForExit() };
    worker.get();
    return result;
  }
  catch (const maidsafe_error& error) {
    LOG(kError) << "This is only designed to be invoked by VaultManager.";
    return maidsafe::ErrorToInt(error);
  }
  catch (const std::exception& e) {
    LOG(kError) << "This is only designed to be invoked by VaultManager: " << e.what();
    return maidsafe::ErrorToInt(maidsafe::MakeError(maidsafe::CommonErrors::invalid_parameter));
  }
}
