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

#ifdef MAIDSAFE_WIN32
#include <windows.h>
#else
#include <signal.h>
#endif

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"

#include "maidsafe/vault_manager/tools/commands/commands.h"
#include "maidsafe/vault_manager/tools/local_network_controller.h"

void ShutDownLocalNetworkController(int /*signal*/) {
  throw MakeError(maidsafe::CommonErrors::success);
}

#ifdef MAIDSAFE_WIN32
BOOL CtrlHandler(DWORD control_type) {
  switch (control_type) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      ShutDownLocalNetworkController(0);
      return TRUE;
    default:
      return FALSE;
  }
}
#endif

int main(int argc, char* argv[]) {
  try {
    boost::filesystem::path script_path;
    // TODO(Fraser#5#): 2014-05-19 - Use program options to input script_path and help
    auto unuseds(maidsafe::log::Logging::Instance().Initialise(argc, argv));
    if (unuseds.size() == 2U)
      script_path = boost::filesystem::path{ std::string{ &unuseds[1][0] } };
    else if (unuseds.size() != 1U)
      BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::invalid_parameter));

    maidsafe::vault_manager::tools::LocalNetworkController local_network_controller{ script_path };

#ifndef MAIDSAFE_WIN32
    signal(SIGINT, ShutDownLocalNetworkController);
    signal(SIGTERM, ShutDownLocalNetworkController);
#else
    SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(CtrlHandler), TRUE);
#endif
    for(;;) {
      local_network_controller.current_command->PrintTitle();
      try {
        local_network_controller.current_command->GetChoice();
      } catch (...) {
        throw;
      }

      local_network_controller.current_command->HandleChoice();
    }
  }
  catch (const maidsafe::maidsafe_error& error) {
    // Success is thrown when Quit option is invoked.
    if ((error.code() == maidsafe::make_error_code(maidsafe::CommonErrors::success)) ||
        (error.code() == maidsafe::make_error_code(maidsafe::CommonErrors::unknown)))
      return 0;
    TLOG(kRed) << boost::diagnostic_information(error) << "\n\n";
    return maidsafe::ErrorToInt(error);
  }
  catch (const std::exception& e) {
    TLOG(kRed) << e.what() << "\n\n";
    return maidsafe::ErrorToInt(maidsafe::MakeError(maidsafe::CommonErrors::unknown));
  }
}
