/*  Copyright 2012 MaidSafe.net limited

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

#include <future>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/program_options.hpp"
#include "boost/regex.hpp"
#include "boost/tokenizer.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/vault_manager.h"
#include "maidsafe/vault_manager/utils.h"

namespace fs = boost::filesystem;
namespace po = boost::program_options;

namespace {

std::promise<void> g_shutdown_promise;

void ShutDownVaultManager(int /*signal*/) {
  std::cout << "Stopping vault_manager." << std::endl;
  g_shutdown_promise.set_value();
}

#ifdef MAIDSAFE_WIN32

enum { kMaidSafeVaultManagerStdException = 0x1, kMaidSafeVaultServiceUnknownException };

SERVICE_STATUS g_service_status;
SERVICE_STATUS_HANDLE g_service_status_handle;
wchar_t g_service_name[22] = L"VaultManager";

void StopService(DWORD exit_code, DWORD error_code) {
  g_service_status.dwCurrentState = SERVICE_STOPPED;
  g_service_status.dwWin32ExitCode = exit_code;
  g_service_status.dwServiceSpecificExitCode = error_code;
  SetServiceStatus(g_service_status_handle, &g_service_status);
}

void ControlHandler(DWORD request) {
  switch (request) {
    case SERVICE_CONTROL_STOP:
      LOG(kInfo) << "MaidSafe VaultManager SERVICE_CONTROL_STOP received - stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      ShutDownVaultManager(0);
      SetServiceStatus(g_service_status_handle, &g_service_status);
      return;
    case SERVICE_CONTROL_SHUTDOWN:
      LOG(kInfo) << "MaidSafe VaultManager SERVICE_CONTROL_SHUTDOWN received - stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      ShutDownVaultManager(0);
      SetServiceStatus(g_service_status_handle, &g_service_status);
      return;
    default:
      break;
  }
  // Report current status
  SetServiceStatus(g_service_status_handle, &g_service_status);
}

void ServiceMain() {
  g_service_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_service_status.dwCurrentState = SERVICE_START_PENDING;
  g_service_status.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
  g_service_status.dwWin32ExitCode = 0;
  g_service_status.dwServiceSpecificExitCode = 0;
  g_service_status.dwCheckPoint = 0;
  g_service_status.dwWaitHint = 0;

  g_service_status_handle = RegisterServiceCtrlHandler(
      g_service_name, reinterpret_cast<LPHANDLER_FUNCTION>(ControlHandler));
  assert(g_service_status_handle != SERVICE_STATUS_HANDLE(0));

  try {
    maidsafe::vault_manager::VaultManager vault_manager;
    g_service_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_service_status_handle, &g_service_status);
    g_shutdown_promise.get_future().get();
    StopService(0, 0);
  } catch (const std::exception& e) {
    LOG(kError) << "Exception: " << e.what();
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, kMaidSafeVaultManagerStdException);
    return;
  } catch (...) {
    LOG(kError) << "Exception of unknown type!";
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, kMaidSafeVaultServiceUnknownException);
  }
}

BOOL CtrlHandler(DWORD control_type) {
  switch (control_type) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      ShutDownVaultManager(0);
      return TRUE;
    default:
      return FALSE;
  }
}

#endif

void HandleProgramOptions(int argc, char** argv) {
  po::options_description options_description("Allowed options");
  options_description.add_options()
#ifdef TESTING
      ("port", po::value<int>(), "Listening port")("vault_path", po::value<std::string>(),
                                                   "Path to the vault executable including name")(
          "root_dir", po::value<std::string>(), "Path to folder of config file")
#endif
          ("help", "produce help message");
  po::variables_map variables_map;
  po::store(
      po::command_line_parser(argc, argv).options(options_description).allow_unregistered().run(),
      variables_map);
  po::notify(variables_map);

  if (variables_map.count("help") != 0) {
    LOG(kError) << "Printing out help menu";
    std::cout << options_description;
    BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::success));
  }

#ifdef TESTING
  typedef maidsafe::tcp::Port Port;
  Port port(maidsafe::kLivePort + 100);
  if (variables_map.count("port") != 0) {
    if (variables_map.at("port").as<int>() < 1025 ||
        variables_map.at("port").as<int>() > std::numeric_limits<Port>::max()) {
      LOG(kError) << "port must lie in range [1025, 65535]";
      BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::invalid_argument));
    }
    port = static_cast<Port>(variables_map["port"].as<int>());
  }

  fs::path root_dir, path_to_vault;
  if (variables_map.count("root_dir") != 0)
    root_dir = variables_map["root_dir"].as<std::string>();
  if (variables_map.count("vault_path") != 0)
    path_to_vault = variables_map["vault_path"].as<std::string>();

  maidsafe::vault_manager::test::SetEnvironment(port, root_dir, path_to_vault);
#endif
}

}  // unnamed namespace

int main(int argc, char** argv) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
#ifdef MAIDSAFE_WIN32
#ifdef TESTING
  try {
    HandleProgramOptions(argc, argv);
    if (SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(CtrlHandler), TRUE)) {
      maidsafe::vault_manager::VaultManager vault_manager;
      g_shutdown_promise.get_future().get();
    } else {
      LOG(kError) << "Failed to set control handler.";
      return -3;
    }
  } catch (const std::exception& e) {
    LOG(kError) << "Error: " << e.what();
    return -4;
  }
#else
  SERVICE_TABLE_ENTRY service_table[2];
  service_table[0].lpServiceName = g_service_name;
  service_table[0].lpServiceProc = reinterpret_cast<LPSERVICE_MAIN_FUNCTION>(ServiceMain);
  service_table[1].lpServiceName = NULL;
  service_table[1].lpServiceProc = NULL;
  // Start the control dispatcher thread for our service
  StartServiceCtrlDispatcher(service_table);
#endif
#else
  try {
    HandleProgramOptions(argc, argv);
    maidsafe::vault_manager::VaultManager vault_manager;
    std::cout << "Successfully started vault_manager" << std::endl;
    signal(SIGINT, ShutDownVaultManager);
    signal(SIGTERM, ShutDownVaultManager);
    g_shutdown_promise.get_future().get();
    std::cout << "Successfully stopped vault_manager" << std::endl;
  } catch (const std::exception& e) {
    LOG(kError) << "Error: " << e.what();
    return -5;  // TODO(Ben) 2014-11-26: what is this return value?
  }
#endif
  return 0;
}
