/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#ifdef MAIDSAFE_WIN32
#  include <windows.h>
#else
#  include <signal.h>
#endif

#include <thread>
#include <iostream>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/program_options.hpp"
#include "boost/tokenizer.hpp"
#include "boost/thread.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/array.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

#include "maidsafe/private/lifestuff_manager/lifestuff_manager.h"
#include "maidsafe/private/lifestuff_manager/utils.h"


namespace fs = boost::filesystem;
namespace po = boost::program_options;

namespace {

boost::mutex g_mutex;
boost::condition_variable g_cond_var;
bool g_shutdown_service(false);

void ShutDownLifeStuffManager(int /*signal*/) {
  LOG(kInfo) << "Stopping lifestuff_manager.";
  boost::mutex::scoped_lock lock(g_mutex);
  g_shutdown_service = true;
  g_cond_var.notify_one();
}

#ifdef MAIDSAFE_WIN32

enum {
  kMaidSafeLifeStuffManagerStdException = 0x1,
  kMaidSafeVaultServiceUnknownException
};

SERVICE_STATUS g_service_status;
SERVICE_STATUS_HANDLE g_service_status_handle;
wchar_t g_service_name[22] = L"LifeStuffManager";

void StopService(DWORD exit_code, DWORD error_code) {
  g_service_status.dwCurrentState = SERVICE_STOPPED;
  g_service_status.dwWin32ExitCode = exit_code;
  g_service_status.dwServiceSpecificExitCode = error_code;
  SetServiceStatus(g_service_status_handle, &g_service_status);
}

void ControlHandler(DWORD request) {
  switch (request) {
    case SERVICE_CONTROL_STOP:
      LOG(kInfo) << "MaidSafe LifeStuffManager SERVICE_CONTROL_STOP received - stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      ShutDownLifeStuffManager(0);
      SetServiceStatus(g_service_status_handle, &g_service_status);
      return;
    case SERVICE_CONTROL_SHUTDOWN:
      LOG(kInfo) << "MaidSafe LifeStuffManager SERVICE_CONTROL_SHUTDOWN received - stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      ShutDownLifeStuffManager(0);
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

  g_service_status_handle = RegisterServiceCtrlHandler(g_service_name,
      reinterpret_cast<LPHANDLER_FUNCTION>(ControlHandler));
  assert(g_service_status_handle != SERVICE_STATUS_HANDLE(0));

  // maidsafe::log::Logging::instance().AddFilter("common", maidsafe::log::kInfo);
  // maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);

  try {
    maidsafe::priv::lifestuff_manager::LifeStuffManager lifestuff_manager;
    boost::mutex::scoped_lock lock(g_mutex);
    g_service_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_service_status_handle, &g_service_status);
    while (!g_shutdown_service) {
      g_cond_var.timed_wait(lock, boost::posix_time::minutes(1));
    }
    StopService(0, 0);
  }
  catch(const std::exception& e) {
    LOG(kError) << "Exception: " << e.what();
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, kMaidSafeLifeStuffManagerStdException);
    return;
  }
  catch(...) {
    LOG(kError) << "Exception of unknown type!";
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, kMaidSafeVaultServiceUnknownException);
  }
}

BOOL CtrlHandler(DWORD control_type) {
  switch (control_type) {
    case CTRL_C_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
      ShutDownLifeStuffManager(0);
      return TRUE;
    default:
      return FALSE;
  }
}

#endif

}  // unnamed namespace



int main(int argc, char** argv) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
#ifdef MAIDSAFE_WIN32
#  ifdef TESTING
  po::options_description options_description("Allowed options");
  options_description.add_options()
      ("help", "produce help message")
      ("port", po::value<int>(), "Listening port")
      ("root_dir", po::value<std::string>(), "Path to folder of config file and vault chunkstore");
  try {
    po::variables_map variables_map;
    po::store(po::command_line_parser(argc, argv).options(options_description).
            allow_unregistered().run(), variables_map);
    po::notify(variables_map);

    if (variables_map.count("help")) {
      std::cout << options_description;
      return 1;
    }

    uint16_t port(maidsafe::priv::lifestuff_manager::LifeStuffManager::kDefaultPort() + 100);
    bool has_port(variables_map.count("port") != 0);
    if (has_port) {
      if (variables_map["port"].as<int>() < 1025 ||
          variables_map["port"].as<int>() > std::numeric_limits<uint16_t>::max()) {
        LOG(kError) << "port must lie in range [1025, 65535]";
        return 1;
      }
      port = static_cast<uint16_t>(variables_map["port"].as<int>());
    }

    fs::path root_dir;
    bool has_root_dir(variables_map.count("root_dir") != 0);
    if (has_root_dir)
      root_dir = variables_map["root_dir"].as<std::string>();

    maidsafe::priv::lifestuff_manager::detail::SetTestEnvironmentVariables(port, root_dir);

    if (SetConsoleCtrlHandler(reinterpret_cast<PHANDLER_ROUTINE>(CtrlHandler), TRUE)) {
      maidsafe::priv::lifestuff_manager::LifeStuffManager lifestuff_manager;
      boost::mutex::scoped_lock lock(g_mutex);
      g_cond_var.wait(lock, [&] { return g_shutdown_service; });  // NOLINT
    } else {
      LOG(kError) << "Failed to set control handler.";
      return 1;
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << "Error: " << e.what();
    return 1;
  }
#  else
  SERVICE_TABLE_ENTRY service_table[2];
  service_table[0].lpServiceName = g_service_name;
  service_table[0].lpServiceProc = reinterpret_cast<LPSERVICE_MAIN_FUNCTION>(ServiceMain);
  service_table[1].lpServiceName = NULL;
  service_table[1].lpServiceProc = NULL;
  // Start the control dispatcher thread for our service
  StartServiceCtrlDispatcher(service_table);
#  endif
#else
  po::options_description options_description("Allowed options");
  options_description.add_options()
      ("help", "produce help message")
      ("port", po::value<int>(), "Listening port")
      ("root_dir", po::value<std::string>(), "Path to folder of config file and vault chunkstore");
  try {
    po::variables_map variables_map;
    po::store(po::command_line_parser(argc, argv).options(options_description).
            allow_unregistered().run(), variables_map);
    po::notify(variables_map);

    if (variables_map.count("help")) {
      std::cout << options_description;
      return 1;
    }

    uint16_t port(maidsafe::priv::lifestuff_manager::LifeStuffManager::kDefaultPort() + 100);
    bool has_port(variables_map.count("port") != 0);
    if (has_port) {
      if (variables_map["port"].as<int>() < 1025 ||
          variables_map["port"].as<int>() > std::numeric_limits<uint16_t>::max()) {
        LOG(kError) << "port must lie in range [1025, 65535]";
        return 1;
      }
      port = static_cast<uint16_t>(variables_map["port"].as<int>());
    }

    fs::path root_dir;
    bool has_root_dir(variables_map.count("root_dir") != 0);
    if (has_root_dir)
      root_dir = variables_map["root_dir"].as<std::string>();

    maidsafe::priv::lifestuff_manager::detail::SetTestEnvironmentVariables(port, root_dir);

    maidsafe::priv::lifestuff_manager::LifeStuffManager lifestuff_manager;
    signal(SIGINT, ShutDownLifeStuffManager);
    boost::mutex::scoped_lock lock(g_mutex);
    g_cond_var.wait(lock, [&] { return g_shutdown_service; });  // NOLINT (Philip)
  }
  catch(const std::exception& e) {
    LOG(kError) << "Error: " << e.what();
    return 1;
  }
#endif
  return 0;
}

