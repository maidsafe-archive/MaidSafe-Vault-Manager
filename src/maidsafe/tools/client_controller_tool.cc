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

#include "boost/filesystem/path.hpp"
#include "boost/filesystem/operations.hpp"
#include "boost/program_options.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/detail/fob.h"

#include "maidsafe/lifestuff_manager/client_controller.h"
#include "maidsafe/lifestuff_manager/utils.h"

#include "maidsafe/lifestuff_manager/shared_memory_communication.h"

namespace fs = boost::filesystem;
namespace po = boost::program_options;

int main(int argc, char** /*argv[]*/) {
  if (argc == 2) {
    boost::interprocess::shared_memory_object shared_memory(
        boost::interprocess::open_or_create, "lifestuff_manager", boost::interprocess::read_write);
    boost::interprocess::shared_memory_object::remove("lifestuff_manager");
    std::cout << "delete mem" << std::endl;
  } else if (argc == 1) {
    maidsafe::lifestuff_manager::LifeStuffManagerAddressGetter address_getter;
    try {
      std::cout << "client tool got instance address: "
                << maidsafe::HexEncode(address_getter.GetAddress().value) << std::endl;
    }
    catch (const std::exception& e) {
      std::cout << e.what() << std::endl;
    }
  }

  //  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  //  try {
  //    po::options_description options_description("Allowed options");
  //    options_description.add_options()
  //        ("help,h", "produce help message")
  //        ("identity_index,i", po::value<int>(), "Entry from keys file to use as ID")
  //        ("chunk_path,c", po::value<std::string>(), "Directory to store chunks in")
  //        ("keys_path,k",
  //         po::value<std::string>()->default_value((fs::temp_directory_path() /
  //                                                  "key_directory.dat").string()),
  //         "Path to keys file");
  //    po::variables_map variables_map;
  //    po::store(po::command_line_parser(argc, argv).options(options_description).
  //                  allow_unregistered().run(),
  //              variables_map);
  //    po::notify(variables_map);
  //    if (variables_map.count("help") != 0) {
  //      std::cout << options_description;
  //      return 0;
  //    }

  //    std::vector<maidsafe::passport::detail::AnmaidToPmid> key_chains(
  //        maidsafe::passport::detail::ReadKeyChainList(
  //            variables_map.at("keys_path").as<std::string>()));
  //    if (variables_map.count("chunk_path") == 0 ||
  //        variables_map.count("identity_index") == 0 ||
  //        size_t(variables_map.at("identity_index").as<int>()) >= key_chains.size()) {
  //      std::cout << options_description;
  //      return -1;
  //    }

  //    int index(variables_map.at("identity_index").as<int>());
  //    maidsafe::lifestuff_manager::detail::SetIdentityIndex(index);
  //    maidsafe::lifestuff_manager::ClientController controller(
  //        [] (const maidsafe::NonEmptyString& /*new_version*/) {});
  //    if (controller.StartVault(key_chains.at(index).pmid,
  //                              key_chains.at(index).maid.name(),
  //                              fs::path(variables_map.at("chunk_path").as<std::string>()))) {
  //      std::cout << "Failed to start vault." << std::endl;
  //      return -1;
  //    }
  return 0;
  //  }
  //  catch(...) { return -1 ; }
}
