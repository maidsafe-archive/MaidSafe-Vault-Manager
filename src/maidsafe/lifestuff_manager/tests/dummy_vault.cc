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

#include "boost/asio/ip/udp.hpp"
#include "boost/program_options.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff_manager/vault_controller.h"

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
  LOG(kInfo) << "Starting dummy_vault.";
  po::options_description options_description("Allowed options");
  options_description.add_options()
      ("help", "produce help message")
      ("runtime", po::value<int>(), "Set runtime in seconds then crash")
      ("nocrash", "set no crash on runtime ended")
      ("vmid", po::value<std::string>(), "vaults manager ID")
      ("nocontroller", "set to use no vault controller")
      ("usr_id", po::value<std::string>()->default_value("lifestuff"),
          "user id if running in non-win OS and from inside a process");
  try {
    po::variables_map variables_map;
    po::store(po::command_line_parser(argc, argv).options(options_description).
            allow_unregistered().run(), variables_map);
    po::notify(variables_map);

    if (variables_map.count("help")) {
      std::cout << options_description;
      return -1;
    }
    if (!variables_map.count("vmid")) {
      LOG(kError) << "dummy_vault: You must supply a vaults manager ID";
      return -2;
    }
    std::string usr_id("lifestuff");
    if (variables_map.count("usr_id"))
      usr_id = variables_map.at("usr_id").as<std::string>();

    std::string lifestuff_manager_id = variables_map["vmid"].as<std::string>();
    if (!variables_map.count("nocontroller")) {
      LOG(kInfo) << "dummy_vault: Starting VaultController: " << usr_id;
      maidsafe::lifestuff_manager::VaultController vault_controller(usr_id);
      if (!vault_controller.Start(lifestuff_manager_id.c_str(), [&] { StopHandler(); })) {  // NOLINT
        LOG(kError) << "dummy_vault: Vault controller failed to start. Aborting...";
        return -3;
      }

      std::unique_ptr<maidsafe::passport::Pmid> pmid;
      std::vector<boost::asio::ip::udp::endpoint> bootstrap_endpoints;
      vault_controller.GetIdentity(pmid, bootstrap_endpoints);
      LOG(kInfo) << "dummy_vault: Identity: " << maidsafe::Base64Substr(pmid->name().data);
      LOG(kInfo) << "Validation Token: "
                 << maidsafe::Base64Substr(pmid->validation_token().string());
      LOG(kInfo) << "Public Key: "
                 << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(pmid->public_key()));
      LOG(kInfo) << "Private Key: "
                 << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(pmid->private_key()));
      vault_controller.ConfirmJoin();

      boost::asio::ip::udp::endpoint endpoint;
      endpoint.address(boost::asio::ip::address::from_string("127.0.0.46"));
      endpoint.port(3658);
      vault_controller.SendEndpointToLifeStuffManager(endpoint);
      std::unique_lock<std::mutex> lock(mutex);
      cond_var.wait(lock, [] { return g_check_finished; });  // NOLINT (Fraser)
    }

    if (variables_map.count("runtime")) {
      int runtime = variables_map["runtime"].as<int>();
      LOG(kInfo) << "Running for " << runtime << " seconds.";
      maidsafe::Sleep(boost::posix_time::seconds(runtime));
      if (variables_map.count("nocrash")) {
        g_check_finished = true;
        LOG(kInfo) << "dummy_vault: Process finishing normally. ";
        return 0;
      } else {
        return -4;
      }
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << "Error: " << e.what();
    return -5;
  }
}
