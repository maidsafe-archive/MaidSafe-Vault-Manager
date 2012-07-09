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

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

namespace maidsafe {

namespace priv {

  VaultManager::VaultManager() : p_id_vector_(), process_vector_(), manager_() {}

  VaultManager::~VaultManager() {}

  void VaultManager::RunVault(std::string chunkstore_path, std::string chunkstore_capacity,
                              bool new_vault) {
    maidsafe::Process process;
    int_fast32_t p_id;
    std::cout << "CREATING A VAULT at location: " << chunkstore_path << ", with capacity: "
              << chunkstore_capacity << std::endl;

    process.SetProcessName("pd-vault");
    process.AddArgument("pd-vault");
    process.AddArgument("--chunkstore_path");
    process.AddArgument(chunkstore_path);
    process.AddArgument("--chunkstore_capacity");
    process.AddArgument(chunkstore_capacity);
    process.AddArgument("--vault_id_path");
    process.AddArgument("/home/nikola/idpath.txt");
    process.AddArgument("--start");
    process_vector_.push_back(process);

    p_id = manager_.AddProcess(process);
    p_id_vector_.push_back(p_id);

    manager_.StartProcess(p_id);

    if (new_vault) {
      WriteConfig();
    }
  }

  void VaultManager::RestartVault(int32_t id) {
    manager_.RestartProcess(id);
  }

  void VaultManager::StopVault(int32_t id) {
    manager_.KillProcess(p_id_vector_[id]);
//     manager_.StopProcess(p_id_vector_[id]); This is to be put in function when the
//     new model od process manager will work properly
  }

  void VaultManager::EraseVault(int32_t id) {
      process_vector_.erase(process_vector_.begin() + (id - 1));
      manager_.KillProcess(p_id_vector_[id - 1]);
      p_id_vector_.erase(p_id_vector_.begin() + (id - 1));
      std::cout << "Erasing vault..." << std::endl;
      if (WriteConfig()) {
        std::cout << "Done!\n" << std::endl;
      }
  }

  bool VaultManager::WriteConfig() {
    std::vector<std::string> vault_info;
    fs::path path("TestConfig.txt");

    std::string content = "";

    for (int i = 0; i < process_vector_.size(); i++) {
      if (i != 0)
      {
        content += "\n";
      }
      vault_info = process_vector_[i].Args();
      content += vault_info[2] + " " + vault_info[4];
      vault_info.clear();
    }

    return maidsafe::WriteFile(path, content);
  }

  bool VaultManager::ReadConfig() {
    fs::path path("TestConfig.txt");
    std::string content;

    maidsafe::ReadFile(path, &content);

    typedef boost::tokenizer<boost::char_separator<char> > vault_tokenizer;
    boost::char_separator<char> delimiter("\n", "", boost::keep_empty_tokens);
    vault_tokenizer tok(content, delimiter);

    for (vault_tokenizer::iterator iterator = tok.begin(); iterator != tok.end(); ++iterator) {
       std::string argument = *iterator;

       typedef boost::tokenizer<boost::char_separator<char> > argument_tokenizer;
       boost::char_separator<char> argument_delimiter(" ", "", boost::keep_empty_tokens);
       argument_tokenizer arg_tokenizer(argument, argument_delimiter);
       std::vector<std::string> vault(arg_tokenizer.begin(), arg_tokenizer.end());
       RunVault(vault[0], vault[1], false);
    }
  }

  int32_t VaultManager::ListVaults(bool select) {
    fs::path path("TestConfig.txt");
    std::string content;

    maidsafe::ReadFile(path, &content);

    typedef boost::tokenizer<boost::char_separator<char> > vault_tokenizer;
    boost::char_separator<char> delimiter("\n", "", boost::keep_empty_tokens);
    vault_tokenizer tok(content, delimiter);

    int32_t i = 1;
    std::cout << "\n************************************************************\n" << std::endl;
    for (vault_tokenizer::iterator iterator = tok.begin(); iterator != tok.end(); ++iterator) {
      std::cout << i << ". " << *iterator << std::endl;
      i++;
    }
    std::cout << "\n************************************************************\n" << std::endl;

    if (select) {
      int32_t option;
      std::cout << "Select an item: ";
      std::cin >> option;
      return option;
    }

    return 0;
  }

  int32_t VaultManager::get_process_vector_size() {
    return process_vector_.size();
  }
}       // namespace priv
}       // namespace maidsafe

int main(int argc, char **argv) {
  maidsafe::log::Logging::instance().AddFilter("common", maidsafe::log::kInfo);
//   maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);
  maidsafe::ProcessManager manager;
  maidsafe::priv::VaultManager vman;

  vman.ReadConfig();

  int32_t stdinput;
  std::string options = "1. (Start a new vault)\n";
  options.append("2. (Start a stopped vault)\n");
  options.append("3. (Stop a vault)\n");
  options.append("4. (Erase a vault)\n");
  options.append("5. (List all vaults)\n");
  options.append("6. (Quit)\n");

  bool exit = false;

  std::string size;
  std::string option = "";
  while (!exit && (std::cout << options) && (std::cin >> stdinput))
  {
    switch (stdinput) {
      case 1:
        std::cout << "Enter vault capacity: ";
        std::cin >> size;
        vman.RunVault((maidsafe::GetSystemAppDir()/"TestVault").string() +
                        maidsafe::RandomAlphaNumericString(5) + "/", size, true);
        break;
      case 2:
        vman.RestartVault(vman.ListVaults(true));
        break;
      case 3:
        vman.StopVault(vman.ListVaults(true));
        std::cout << "Wait for this!\n";
        break;
      case 4:
        vman.EraseVault(vman.ListVaults(true));
        break;
      case 5:
        vman.ListVaults(false);
        std::cout << "Number of currently active vaults: " << vman.get_process_vector_size()
                  << "\n\n";
        break;
      case 6:
        exit = true;
        break;
    }
  }
  std::cout << "Exiting..." << std::endl;
//  int32_t p_id;
//  std::vector<int32_t> p_idd;
//  fs::path filename ("/home/nikola/idpath.txt");
//  maidsafe::rsa::Keys key;
//  key.identity = maidsafe::RandomString(64);
//  maidsafe::rsa::GenerateKeyPair(&key);
//  try {
//
//     if (!fs::exists(filename.parent_path()))
//       LOG(kInfo) << "PATH DOESN'T EXIST" <<std::endl;
//
//     fs::ofstream ofs(filename);
//     LOG(kInfo) << "POSLE2" <<std::endl;
//     boost::archive::text_oarchive oa(ofs);
//     oa & key.identity;
//     oa & key.public_key;
//     oa & key.private_key;
//
//     LOG(kInfo) << "Updated vault identity." << std::endl;
//
//   for (int i = 0; i < 1; i++)
//   {
//     maidsafe::Process process, process2;
//     std::cout<<"CREATING A PROCESS "<< i+1 <<std::endl;
//
//     std::cout<<"VAULT"<<std::endl;
//     process.SetProcessName("pd-vault");
//     process.AddArgument("pd-vault");
//     process.AddArgument("--chunkstore_path");
//     process.AddArgument("/home/nikola/test/");
// //     process.AddArgument((maidsafe::GetSystemAppDir()/"TestVault").string() +
//                               maidsafe::IntToString(i));
//     process.AddArgument("--chunkstore_capacity");
//     process.AddArgument("0");
//     process.AddArgument("--vault_id_path");
//     process.AddArgument("/home/nikola/idpath.txt");
//     process.AddArgument("--start");
//
//     p_id = manager.AddProcess(process);
//     p_idd.push_back(p_id);
//     manager.StartProcess(p_id);
//
// //     std::cout<<"DUMMY with vault controller"<<std::endl;
// //     process2.SetProcessName("DUMMYprocess");
// //     process2.AddArgument("DUMMYprocess");
// //     process2.AddArgument("--runtime");
// //     process2.AddArgument("365");
// //     process2.AddArgument("--nocrash");
// //
// //     p_id = manager.AddProcess(process2);
// //     p_idd.push_back(p_id);
// //     std::cout<<"STARTING PROCESS WITH PROCESS ID: " << p_id <<std::endl;
// //     manager.StartProcess(p_id);
//
//     boost::this_thread::sleep(boost::posix_time::seconds(1));
//   }
//
//   for (int i = 0; i < 450; i++) {
//     boost::this_thread::sleep(boost::posix_time::seconds(1));
//     std::cout << "\nRUNNNIG FOR: " << i << " SECONDS" << std::endl;
//   }
//
//     std::cout << "ID VECTOR SIZE IS: " << p_idd.size() << std::endl;
//   for(int i = 0 ; i < 1; i++)
//   {
//     std::cout<<"KILLING PROCESS: "<< i << " WITH PROCESS ID: " << p_idd[i] << std::endl;
//     manager.KillProcess(p_idd[i]);
//   }
//
//    manager.KillProcess(0);
//    manager.KillProcess(1);
// }
//   catch(std::exception& e)  {
//     std::cout << "EEEEEERRRROOOR" << e.what() << "\n";
//     return false;
//   }
  return 0;
}
