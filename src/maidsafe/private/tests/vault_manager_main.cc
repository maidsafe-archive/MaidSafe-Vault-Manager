/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "maidsafe/private/vault_manager.h"

#include <thread>
#include <boost/graph/graph_concepts.hpp>

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

#ifdef WIN32

#include <windows.h>

enum {
  MAIDSAFE_VAULT_MANAGER_STD_EXCEPTION = 0x1,
  MAIDSAFE_VAULT_SERVICE_UNKNOWN_EXCEPTION
};

boost::mutex mutex_;
boost::condition_variable cond_var_;
bool shutdown_service(false);

namespace {
  SERVICE_STATUS g_service_status;
  SERVICE_STATUS_HANDLE g_service_status_handle;
  wchar_t g_service_name[21] = L"MaidSafeVaultManager";
}  // unnamed namespace

void shutdown() {
  LOG(kInfo) << "Stopping vault_manager.";
  boost::mutex::scoped_lock lock(mutex_);
  shutdown_service = true;
  cond_var_.notify_one();
}

void StopService(DWORD exit_code, DWORD error_code) {
  g_service_status.dwCurrentState = SERVICE_STOPPED;
  g_service_status.dwWin32ExitCode = exit_code;
  g_service_status.dwServiceSpecificExitCode = error_code;
  SetServiceStatus(g_service_status_handle, &g_service_status);
}

void ServiceMain();
void ControlHandler(DWORD request);

#endif

int main(int /*argc*/, char ** /*argv*/) {
#ifdef WIN32

  SERVICE_TABLE_ENTRY service_table[2];
  service_table[0].lpServiceName = g_service_name;
  service_table[0].lpServiceProc = reinterpret_cast<LPSERVICE_MAIN_FUNCTION>(ServiceMain);
  service_table[1].lpServiceName = NULL;
  service_table[1].lpServiceProc = NULL;
  // Start the control dispatcher thread for our service
  StartServiceCtrlDispatcher(service_table);
#else
  maidsafe::log::Logging::instance().AddFilter("common", maidsafe::log::kInfo);
  maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);

  maidsafe::ProcessManager process_manager;
  maidsafe::priv::VaultManager vault_manager;

  /*vault_manager.ReadConfig();*/
  vault_manager.StartListening();
#endif
  return 0;
}

#ifdef WIN32

void ControlHandler(DWORD request) {
  switch (request) {
    case SERVICE_CONTROL_STOP:
      LOG(kInfo) << "MaidSafe VaultManager SERVICE_CONTROL_STOP received - service stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      shutdown();
      SetServiceStatus(g_service_status_handle, &g_service_status);
      return;
    case SERVICE_CONTROL_SHUTDOWN:
      LOG(kInfo) << "MaidSafe VaultManager SERVICE_CONTROL_SHUTDOWN received - service stopping.";
      g_service_status.dwWin32ExitCode = 0;
      g_service_status.dwCurrentState = SERVICE_STOPPED;
      shutdown();
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
    boost::mutex::scoped_lock lock(mutex_);
    g_service_status.dwCurrentState = SERVICE_RUNNING;
    SetServiceStatus(g_service_status_handle, &g_service_status);
    /*vault_manager.ReadConfig();*/
    // vault_manager.StartListening();
    while (!shutdown_service) {
      cond_var_.timed_wait(lock, bptime::minutes(1));
    }
    StopService(0, 0);
    return;
  }
  catch(const std::exception& e) {
    LOG(kError) << "Exception: " << e.what();
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, MAIDSAFE_VAULT_MANAGER_STD_EXCEPTION);
    return;
  }
  catch(...) {
    LOG(kError) << "Exception of unknown type!";
    StopService(ERROR_SERVICE_SPECIFIC_ERROR, MAIDSAFE_VAULT_SERVICE_UNKNOWN_EXCEPTION);
  }

}

#endif