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

#include "boost/tokenizer.hpp"
#include "boost/thread.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/array.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

#include "maidsafe/private/process_management/invigilator.h"


namespace {

boost::mutex g_mutex;
boost::condition_variable g_cond_var;
bool g_shutdown_service(false);

void ShutDownInvigilator(int /*signal*/) {
  LOG(kInfo) << "Stopping invigilator.";
  boost::mutex::scoped_lock lock(g_mutex);
  g_shutdown_service = true;
  g_cond_var.notify_one();
}

#ifdef MAIDSAFE_WIN32

enum {
  kMaidSafeInvigilatorStdException = 0x1,
  kMaidSafeVaultServiceUnknownException
};

SERVICE_STATUS g_service_status;
SERVICE_STATUS_HANDLE g_service_status_handle;
wchar_t g_service_name[22] = L"MaidSafeInvigilator";

void StopService(DWORD exit_code, DWORD error_code) {
  g_service_status.dwCurrentState = SERVICE_STOPPED;
  g_service_status.dwWin32ExitCode = exit_code;
  g_service_status.dwServiceSpecificExitCode = error_code;
  SetServiceStatus(g_service_status_handle, &g_service_status);
}

void ControlHandler(DWORD request) {
  switch (request) {
    case SERVICE_CONTROL_STOP:
      LOG(kInfo) << "MaidSafe Invigilator SERVICE_CONTROL_STOP received - service stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      ShutDownInvigilator(0);
      SetServiceStatus(g_service_status_handle, &g_service_status);
      return;
    case SERVICE_CONTROL_SHUTDOWN:
      LOG(kInfo) << "MaidSafe Invigilator SERVICE_CONTROL_SHUTDOWN received - service stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      ShutDownInvigilator(0);
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
    maidsafe::priv::process_management::Invigilator invigilator;
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
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, kMaidSafeInvigilatorStdException);
    return;
  }
  catch(...) {
    LOG(kError) << "Exception of unknown type!";
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, kMaidSafeVaultServiceUnknownException);
  }
}

BOOL CtrlHandler(DWORD CtrlType) 
{ 
  switch(CtrlType) 
  {  
    case CTRL_C_EVENT: 
    case CTRL_CLOSE_EVENT:  
    case CTRL_SHUTDOWN_EVENT: 
      ShutDownInvigilator(0);
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
#ifdef USE_TEST_KEYS
  if(SetConsoleCtrlHandler((PHANDLER_ROUTINE)CtrlHandler, TRUE)) {
    maidsafe::priv::process_management::Invigilator invigilator;
    boost::mutex::scoped_lock lock(g_mutex);
    g_cond_var.wait(lock, [&] { return g_shutdown_service; });
  } else {
    LOG(kError) << "Failed to set control handler.";
    return 1;
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
  {
    maidsafe::priv::process_management::Invigilator invigilator;
    signal(SIGINT, ShutDownInvigilator);
    boost::mutex::scoped_lock lock(g_mutex);
    g_cond_var.wait(lock, [&] { return g_shutdown_service; });  // NOLINT (Philip)
  }
#endif
  return 0;
}

