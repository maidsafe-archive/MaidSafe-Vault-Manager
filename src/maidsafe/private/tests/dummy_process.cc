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

#include "boost/program_options.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/vault_controller.h"

namespace po = boost::program_options;

namespace {

bool g_check_finished(false);

// bool CheckTerminateFlag(int32_t id, bi::managed_shared_memory& shared_mem) {
//   std::pair<TerminateVector*, std::size_t> t =
//       shared_mem.find<TerminateVector>("terminate_info");
//   size_t size(0);
//   if (t.first) {
//     size = (*t.first).size();
//   } else {
//     std::cout << "CheckTerminateFlag: failed to access IPC shared memory";
//     return false;
//   }
//   if (size <= static_cast<size_t>(id - 1) || id - 1 < 0) {
//     std::cout << "CheckTerminateFlag: given process id is invalid or outwith range of "
//               << "terminate vector";
//     return false;
//   }
//   if ((*t.first).at(id - 1) == TerminateStatus::kTerminate) {
//     std::cout << "Process terminating. ";
//     return true;
//   }
//   return false;
// }
//
// void ListenForTerminate(std::string shared_mem_name, int id) {
//     bi::managed_shared_memory shared_mem(bi::open_or_create,
//                                                           shared_mem_name.c_str(),
//                                                           1024);
//     while (!CheckTerminateFlag(static_cast<int32_t>(id), shared_mem) && !check_finished)
//       maidsafe::Sleep(boost::posix_time::milliseconds(500));
//     if (check_finished)
//       return;
//     exit(0);
// }

void StopHandler() {
  LOG(kInfo) << "Process stopping, asked to stop by parent.";
  exit(0);
}

}  // unnamed namespace


int main(int argc, char* argv[]) {
  LOG(kInfo) << "Starting DUMMYprocess.";
  maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);
  po::options_description options_description("Allowed options");
  options_description.add_options()
      ("help", "produce help message")
      ("runtime", po::value<int>(), "Set runtime in seconds then crash")
      ("nocrash", "set no crash on runtime ended")
      ("vmid", po::value<std::string>(), "vaults manager ID");
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
    std::string vaults_manager_id = variables_map["vmid"].as<std::string>();
    LOG(kInfo) << "DUMMYprocess: Starting VaultController.";
    maidsafe::priv::VaultController vault_controller;
    vault_controller.Start(vaults_manager_id.c_str(), [&] { StopHandler(); });  // NOLINT
    maidsafe::asymm::Keys keys;
    std::string account_name;
    vault_controller.GetIdentity(&keys, &account_name);
    LOG(kInfo) << "DUMMYprocess: Identity: " << (keys.identity);
    LOG(kInfo) << "Validation Token: " << (keys.validation_token);
    std::string public_key_string;
    maidsafe::asymm::EncodePublicKey(keys.public_key, &public_key_string);
    std::string private_key_string;
    maidsafe::asymm::EncodePrivateKey(keys.private_key, &private_key_string);
    LOG(kInfo) << "Public Key: " << maidsafe::Base64Substr(public_key_string);
    LOG(kInfo) << "Private Key: " << maidsafe::Base64Substr(private_key_string);
    LOG(kInfo) << "Account name: " << account_name;
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
    } else {
      for (;;)
        maidsafe::Sleep(boost::posix_time::seconds(1));
    }
  }
  catch(const std::exception& e) {
    LOG(kError) << "Error: " << e.what();
    return 1;
  }
}
