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

#include "maidsafe/private/vault_manager.h"

#ifdef WIN32
#  include <windows.h>
#else
#  include <signal.h>
#endif

#include <thread>
#include <iostream>
#include <string>
#include <vector>

#include "boost/tokenizer.hpp"
#include "boost/thread.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/array.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"
#include "maidsafe/private/message_handler.h"
#include "maidsafe/private/vault_identity_info_pb.h"

namespace {

boost::mutex g_mutex;
boost::condition_variable g_cond_var;
bool g_shutdown_service(false);

void ShutDownVaultManager(int /*signal*/) {
  LOG(kInfo) << "Stopping vault_manager.";
  boost::mutex::scoped_lock lock(g_mutex);
  g_shutdown_service = true;
  g_cond_var.notify_one();
}

#ifdef WIN32

enum {
  kMaidSafeVaultManagerStdException = 0x1,
  kMaidSafeVaultServiceUnknownException
};

SERVICE_STATUS g_service_status;
SERVICE_STATUS_HANDLE g_service_status_handle;
wchar_t g_service_name[21] = L"MaidSafeVaultManager";

void StopService(DWORD exit_code, DWORD error_code) {
  g_service_status.dwCurrentState = SERVICE_STOPPED;
  g_service_status.dwWin32ExitCode = exit_code;
  g_service_status.dwServiceSpecificExitCode = error_code;
  SetServiceStatus(g_service_status_handle, &g_service_status);
}

void ControlHandler(DWORD request) {
  switch (request) {
    case SERVICE_CONTROL_STOP:
      LOG(kInfo) << "MaidSafe VaultManager SERVICE_CONTROL_STOP received - service stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      ShutDownVaultManager(0);
      SetServiceStatus(g_service_status_handle, &g_service_status);
      return;
    case SERVICE_CONTROL_SHUTDOWN:
      LOG(kInfo) << "MaidSafe VaultManager SERVICE_CONTROL_SHUTDOWN received - service stopping.";
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

  g_service_status_handle = RegisterServiceCtrlHandler(g_service_name,
      reinterpret_cast<LPHANDLER_FUNCTION>(ControlHandler));
  assert(g_service_status_handle != SERVICE_STATUS_HANDLE(0));

  // maidsafe::log::Logging::instance().AddFilter("common", maidsafe::log::kInfo);
  // maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);

  maidsafe::ProcessManager process_manager;
  maidsafe::priv::VaultManager vault_manager;

  try {
    boost::mutex::scoped_lock lock(g_mutex);
    g_service_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_service_status_handle, &g_service_status);
    /*vault_manager.ReadConfig();*/
    // vault_manager.StartListening();
    while (!g_shutdown_service) {
      g_cond_var.timed_wait(lock, bptime::minutes(1));
    }
    // vault_manager.StopListening();
    StopService(0, 0);
    return;
  }
  catch(const std::exception& e) {
    LOG(kError) << "Exception: " << e.what();
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, kMaidSafeVaultManagerStdException);
    return;
  }
  catch(...) {
    LOG(kError) << "Exception of unknown type!";
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, kMaidSafeVaultServiceUnknownException);
  }
}

#endif

}  // unnamed namespace



int main() {
#ifdef WIN32
  SERVICE_TABLE_ENTRY service_table[2];
  service_table[0].lpServiceName = g_service_name;
  service_table[0].lpServiceProc = reinterpret_cast<LPSERVICE_MAIN_FUNCTION>(ServiceMain);
  service_table[1].lpServiceName = NULL;
  service_table[1].lpServiceProc = NULL;
  // Start the control dispatcher thread for our service
  StartServiceCtrlDispatcher(service_table);
#else
  signal(SIGINT, ShutDownVaultManager);
  maidsafe::log::Logging::instance().AddFilter("common", maidsafe::log::kInfo);
  maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);
  maidsafe::priv::VaultManager vault_manager;

  vault_manager.ReadConfig();
  vault_manager.StartListening();
  boost::mutex::scoped_lock lock(g_mutex);
  g_cond_var.wait(lock, [&] { return g_shutdown_service; });  // NOLINT (Philip)
  vault_manager.StopListening();
#endif
  return 0;
}

