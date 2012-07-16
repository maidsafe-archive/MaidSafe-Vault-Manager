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

  VaultManager::VaultManager() : p_id_vector_(), process_vector_(), manager_(),
                                 download_manager_() {}

  VaultManager::~VaultManager() {}

  /*void VaultManager::RunVault(std::string chunkstore_path, std::string chunkstore_capacity,
                              bool new_vault) {
    maidsafe::Process process;
    std::string p_id;
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

  void VaultManager::RestartVault(std::string id) {
    manager_.RestartProcess(id);
  }

  void VaultManager::StopVault(std::string id) {
//     manager_.KillProcess(p_id_vector_[id]);
    manager_.StopProcess(p_id_vector_[id]);  // This is to be put in function when the
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

    for (size_t i = 0; i < process_vector_.size(); i++) {
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
    return true;
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
  }*/

  std::pair<std::string, std::string> VaultManager::FindLatestLocalVersion(std::string name,
                                                                           std::string platform,
                                                                           std::string cpu_size) {
    boost::filesystem::path current_path(boost::filesystem::current_path());
    fs::directory_iterator end;
    std::string latest_file(name + "_" + platform + "_" + cpu_size + "_0_0");
    std::string max_version(""), max_patchlevel("");
    for (fs::directory_iterator dir_it(current_path); dir_it != end; ++dir_it) {
      if (!download_manager_.FileIsValid((*dir_it).path().stem().string()))
        continue;
      boost::char_separator<char> sep("_");
      boost::tokenizer<boost::char_separator<char>> tok((*dir_it).path().stem().string(), sep);
      auto it(tok.begin());

      std::string current_name(*it);
      std::cout << "name " << name << std::endl;
      std::cout << "current_name " <<current_name << std::endl;
      if (name != current_name)
        continue;

      std::string current_platform(*(++it));
      std::cout << "platform " << platform << std::endl;
      std::cout << "current_platform " << current_platform << std::endl;
      if (platform != current_platform)
        continue;

      std::string current_cpu_size(*(++it));
      std::cout << "cpu_size " << cpu_size << std::endl;
      std::cout << "current_cpu_size " << current_cpu_size << std::endl;
      if (cpu_size != current_cpu_size)
        continue;
      std::cout << "(*dir_it).path().stem().string(): " << (*dir_it).path().stem().string()
                << std::endl;
      std::cout << "latest_file: " << latest_file << std::endl;

//       std::string maxversion2 (*(++it));
//       std::string maxpatch2 (*(++it));
//       std::cout << "max_version2: " << maxversion2 << std::endl;
//       std::cout << "maxpatch2: " << maxpatch2 << std::endl;

      std::string temp_max_version = *(++it);
      std::string temp_max_patchlevel = *(++it);

//       if (download_manager_.FileIsLaterThan((*dir_it).path().filename().string(), latest_file)) {
      if (download_manager_.FileIsLaterThan((*dir_it).path().stem().string(), latest_file)) {
        std::cout << "(*dir_it).path().stem().string() FOR SECOND TIME: "
                  << (*dir_it).path().stem().string() << std::endl;
        latest_file = (*dir_it).path().stem().string();
        max_version = temp_max_version;
        max_patchlevel = temp_max_patchlevel;
      }
    }
    return std::pair<std::string, std::string>(max_version, max_patchlevel);
  }

  void VaultManager::ListenForUpdates() {
    std::string name("lifestufflocal");
    int32_t cpu_size(maidsafe::CpuSize());
    std::string platform;
    std::string extension = "";

    #ifdef _WINDOWS
    platform = "win";
    extension = ".exe"
    #elifdef _APPLE_
    platform = "osx";
    #else
    platform = "linux";
    #endif

    std::string current_version, current_patchlevel;
    std::pair<std::string, std::string> version_and_patchlevel;
    boost::filesystem::path current_path(boost::filesystem::current_path());
    std::cout << current_path << std::endl;
    while (true) {
      std::cout << "FINDING LATEST LOCAL VERSION OF " << name << std::endl;
      version_and_patchlevel = FindLatestLocalVersion(name, platform,
                                                      boost::lexical_cast<std::string>(cpu_size));
      std::cout << "CPU SIZE: " << cpu_size << std::endl;
      current_version = version_and_patchlevel.first;
      current_patchlevel = version_and_patchlevel.second;
      std::cout << "LATEST LOCAL VERSION OF " << name << " IS "
                                              << version_and_patchlevel.first << "_"
                                              << version_and_patchlevel.second << std::endl;
      download_manager_ = DownloadManager("dash.maidsafe.net", "~phil", name,
                                          platform, boost::lexical_cast<std::string>(cpu_size),
                                          current_version, current_patchlevel);

      std::cout << "INITIALISED DOWNLOAD MANAGER" << std::endl;
      if (download_manager_.FindLatestFile()) {
        std::string file_to_download(download_manager_.file_to_download());

        // Download the signature file
        std::string signature_file = file_to_download + extension + ".sig";
        std::cout << "SIGNATURE FILE IS " << signature_file << std::endl;
        download_manager_.SetFileToDownload(signature_file);
        download_manager_.UpdateCurrentFile(current_path);
        std::cout << "SIGNATURE FILE " << signature_file << " HAS BEEN DOWNLOADED." << std::endl;

        // Download the client file
        file_to_download = file_to_download +  extension;
        std::cout << "FILE FOUND TO BE DOWNLOADED, " << file_to_download  << std::endl;
        download_manager_.SetFileToDownload(file_to_download);
        download_manager_.UpdateCurrentFile(current_path);
        std::cout << "UPDATED " << name << " TO " << file_to_download << std::endl;

        if (download_manager_.VerifySignature()) {
          // Remove the signature_file
          std::cout << "REMOVING SIGNATURE FILE" << std::endl;
          boost::filesystem::remove(current_path / signature_file);
        } else {
          std::cout << "Invalid Signature" << std::endl;
          // Remove the signature_file
          boost::filesystem::remove(current_path / signature_file);
          boost::filesystem::remove(current_path / file_to_download);
        }
      } else {
        std::cout << "LATEST FILE NOT FOUND, " << std::endl;
      }
      std::cout << "Sleeping for five minutes! " << std::endl;
      boost::this_thread::sleep(boost::posix_time::minutes(5));
    }
  }

}       // namespace priv
}       // namespace maidsafe

int main(int /*argc*/, char **/*argv*/) {
  maidsafe::log::Logging::instance().AddFilter("common", maidsafe::log::kInfo);
  maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kInfo);
  maidsafe::ProcessManager manager;
  maidsafe::priv::VaultManager vman;

  /*vman.ReadConfig();*/

  // sint32_t stdinput;
  std::string options = "1. (Start a new vault)\n";
  options.append("2. (Start a stopped vault)\n");
  options.append("3. (Stop a vault)\n");
  options.append("4. (Erase a vault)\n");
  options.append("5. (List all vaults)\n");
  options.append("6. (Quit)\n");

  // bool exit = false;

  std::string size;
  std::string option = "";
  /*while (!exit && (std::cout << options) && (std::cin >> stdinput))
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
  }*/

  std::thread thd( [&] { vman.ListenForUpdates(); } ); // NOLINT
  if (thd.joinable())
    thd.join();

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
