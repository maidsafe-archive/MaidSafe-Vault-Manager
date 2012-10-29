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

#include <string>
#include <mutex>
#include <condition_variable>

#include "boost/program_options.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/utils/fob.h"
#include "maidsafe/private/process_management/vault_controller.h"

namespace po = boost::program_options;

namespace {

bool g_check_finished(false);

std::mutex mutex;
std::condition_variable cond_var;

void StopHandler() {
  LOG(kInfo) << "Process stopping, asked to stop by parent.";
  std::lock_guard<std::mutex> lock(mutex);
  g_check_finished = true;
  cond_var.notify_all();
}

}  // unnamed namespace


int main(int argc, char* argv[]) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  LOG(kInfo) << "Starting DUMMYprocess.";
  po::options_description options_description("Allowed options");
  options_description.add_options()
      ("help", "produce help message")
      ("runtime", po::value<int>(), "Set runtime in seconds then crash")
      ("nocrash", "set no crash on runtime ended")
      ("vmid", po::value<std::string>(), "vaults manager ID")
      ("nocontroller", "set to use no vault controller");
  try {
    po::variables_map variables_map;
    po::store(po::parse_command_line(argc, argv, options_description), variables_map);
    po::notify(variables_map);

    if (variables_map.count("help")) {
        LOG(kInfo) << options_description;
        return 1;
    }
    if (!variables_map.count("vmid")) {
      LOG(kInfo) << "DUMMYprocess: You must supply a vaults manager ID";
      return 1;
    }
    std::string invigilator_id = variables_map["vmid"].as<std::string>();
    if (!variables_map.count("nocontroller")) {
      LOG(kInfo) << "DUMMYprocess: Starting VaultController.";
      maidsafe::priv::process_management::VaultController vault_controller;
      if (!vault_controller.Start(invigilator_id.c_str(), [&] { StopHandler(); })) {  // NOLINT
        LOG(kInfo) << "DUMMYprocess: Vault controller failed to start. Aborting...";
        return 1;
      }

      maidsafe::Fob fob;
      std::string account_name;
      std::vector<std::pair<std::string, uint16_t>> bootstrap_endpoints;
      vault_controller.GetIdentity(fob, account_name, bootstrap_endpoints);
      LOG(kInfo) << "DUMMYprocess: Identity: " << (fob.identity.string());
      LOG(kInfo) << "Validation Token: " << (fob.validation_token.string());
      LOG(kInfo) << "Public Key: "
                 << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(fob.keys.public_key));
      LOG(kInfo) << "Private Key: "
                 << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(fob.keys.private_key));
      LOG(kInfo) << "Account name: " << account_name;
      vault_controller.ConfirmJoin(true);

      std::pair<std::string, uint16_t> endpoint("127.0.0.46", 3658);
      vault_controller.SendEndpointToInvigilator(endpoint);
      std::unique_lock<std::mutex> lock(mutex);
      cond_var.wait(lock, [] { return g_check_finished; });  // NOLINT (Fraser)
    }

    if (variables_map.count("runtime")) {
      int runtime = variables_map["runtime"].as<int>();
      LOG(kInfo) << "Running for " << runtime << " seconds.";
      maidsafe::Sleep(boost::posix_time::seconds(runtime));
      if (variables_map.count("nocrash")) {
        g_check_finished = true;
        LOG(kInfo) << "DUMMYprocess: Process finishing normally. ";
        return 0;
      } else {
        return 1;
      }
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << "Error: " << e.what();
    return 1;
  }
}
