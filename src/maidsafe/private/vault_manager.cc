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
#include "boost/array.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"
#include "maidsafe/private/message_handler.h"
#include "maidsafe/private/vault_identity_info.pb.h"

namespace bai = boost::asio::ip;

namespace maidsafe {

namespace priv {

  /*WaitingVaultInfo::WaitingVaultInfo(const WaitingVaultInfo& other)
      : vault_vmid(), client_endpoint(), account_name(), keys(), chunkstore_path(),
        chunkstore_capacity(), mutex_(), cond_var_(), vault_requested_() {
    vault_vmid = other.vault_vmid;
    client_endpoint = other.client_endpoint;
    account_name = other.account_name;
    keys = other.keys;
    chunkstore_path = other.chunkstore_path;
    chunkstore_capacity = other.chunkstore_capacity;
    mutex_ = other.mutex_;
    cond_var_ = other.cond_var_;
    vault_requested_ = other.vault_requested_;
  }*/

  VaultManager::VaultManager() : vmid_vector_(), process_vector_(), manager_(),
                                 download_manager_(), asio_service_(new AsioService(3)),
                                 msg_handler_(),
                                 transport_(new TcpTransport(asio_service_->service())),
                                 local_port_(5483), client_started_vault_vmids_(),
                                 config_file_vault_vmids_() {
                                   asio_service_->Start();
                                }

  VaultManager::~VaultManager() {}

//   VaultManager::VaultManager(const maidsafe::priv::VaultManager& /*vman*/)
//       : vmid_vector_(),
//         process_vector_(),
//         manager_(),
//         download_manager_(),
//         asio_service_(new AsioService(10)),
//         msg_handler_(),
//         transport_(new TcpTransport(asio_service_->service())),
//         local_port_(5483),
//         client_started_vault_vmids_(),
//         config_file_vault_vmids_() {}

  std::string VaultManager::RunVault(std::string chunkstore_path, std::string chunkstore_capacity,
                              bool new_vault) {
    maidsafe::Process process;
    std::string vmid;
    std::cout << "CREATING A VAULT at location: " << chunkstore_path << ", with capacity: "
              << chunkstore_capacity << std::endl;

    process.SetProcessName("pd-vault");
    process.AddArgument("pd-vault");
    process.AddArgument("--chunk_path");
    process.AddArgument(chunkstore_path);
    process.AddArgument("--chunk_capacity");
    process.AddArgument(chunkstore_capacity);
    process.AddArgument("--start");

    /*process.SetProcessName("DUMMYprocess");
    process.AddArgument("DUMMYprocess");
    process.AddArgument("--nocrash");*/

    process_vector_.push_back(process);

    vmid = manager_.AddProcess(process);
    vmid_vector_.push_back(vmid);

    manager_.StartProcess(vmid);

    if (new_vault) {
      // WriteConfig();
    }
    return vmid;
  }

  void VaultManager::RestartVault(std::string id) {
    manager_.RestartProcess(id);
  }

  void VaultManager::StopVault(int32_t id) {
//     manager_.KillProcess(vmid_vector_[id]);
    manager_.StopProcess(vmid_vector_[id]);  // This is to be put in function when the
//     new model od process manager will work properly
  }

  void VaultManager::EraseVault(int32_t id) {
      process_vector_.erase(process_vector_.begin() + (id - 1));
      manager_.KillProcess(vmid_vector_[id - 1]);
      vmid_vector_.erase(vmid_vector_.begin() + (id - 1));
      std::cout << "Erasing vault..." << std::endl;
      if (WriteConfig()) {
        std::cout << "Done!\n" << std::endl;
      }
  }

  bool VaultManager::WriteConfig() {
    std::vector<std::string> vault_info;
    fs::path path("TestConfig.txt");

    std::string content = "";

    for (size_t i = 0; i < config_file_vault_vmids_.size(); i++) {
      if (i != 0)
      {
        content += "\n";
      }
      std::string serialized_keys = "";
      maidsafe::rsa::SerialiseKeys(config_file_vault_vmids_[i]->keys, serialized_keys);
      content += config_file_vault_vmids_[i]->chunkstore_path + " "
                  + config_file_vault_vmids_[i]->chunkstore_capacity + " " + serialized_keys + " "
                  + config_file_vault_vmids_[i]->account_name;
    }

    for (size_t i = 0; i < client_started_vault_vmids_.size(); i++) {
      if (i != 0)
      {
        content += "\n";
      }
      std::string serialized_keys = "";
      maidsafe::rsa::SerialiseKeys(client_started_vault_vmids_[i]->keys, serialized_keys);
      content += client_started_vault_vmids_[i]->chunkstore_path + " "
                  + client_started_vault_vmids_[i]->chunkstore_capacity + " " + serialized_keys
                  + " " + client_started_vault_vmids_[i]->account_name;
    }

    return maidsafe::WriteFile(path, content);
  }

  bool VaultManager::ReadConfig() {
    fs::path path((GetSystemAppDir()/"config.txt"));
    std::string content;
    LOG(kInfo) << path.string();
    maidsafe::ReadFile(path, &content);

    typedef boost::tokenizer<boost::char_separator<char> > vault_tokenizer;
    boost::char_separator<char> delimiter("\n");
    vault_tokenizer tok(content, delimiter);

    for (vault_tokenizer::iterator iterator = tok.begin(); iterator != tok.end(); ++iterator) {
      std::string argument = *iterator;

      typedef boost::tokenizer<boost::char_separator<char> > argument_tokenizer;
      boost::char_separator<char> argument_delimiter(" ", "", boost::keep_empty_tokens);
      argument_tokenizer arg_tokenizer(argument, argument_delimiter);
      std::vector<std::string> vault_item(arg_tokenizer.begin(), arg_tokenizer.end());
      std::cout << "Location: " << vault_item[0] << std::endl;
      std::cout << "Size: " << vault_item[1] << std::endl;
      std::cout << "Serialized: " << vault_item[2] << std::endl;
      std::cout << "Account name: " << vault_item[3] << std::endl;

      asymm::Keys keys;
      if (!maidsafe::rsa::ParseKeys(vault_item[2], keys))
        LOG(kInfo) << "Error parsing the keys!!!";

      std::shared_ptr<WaitingVaultInfo> vault_info(new WaitingVaultInfo());
      vault_info->keys = keys;
      vault_info->account_name = vault_item[3];

      std::string vmid;
      vmid = RunVault(vault_item[0], vault_item[1], false);

      vault_info->vault_vmid = vmid;
      config_file_vault_vmids_.push_back(vault_info);
    }
    return true;
  }

  int32_t VaultManager::ListVaults(bool select) {
    fs::path path((GetSystemAppDir()/"config.txt"));
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

      std::string filename((*dir_it).path().stem().string());
      typedef boost::tokenizer<boost::char_separator<char> > name_tokenizer;
      boost::char_separator<char> delimiter("_");
      name_tokenizer tok(filename, delimiter);
      name_tokenizer::iterator it = tok.begin();

      std::string current_name(*it);
      LOG(kInfo) << "name " << name;
      LOG(kInfo) << "current_name " << current_name;
      if (name != current_name)
        continue;

      std::string current_platform(*(++it));
      LOG(kInfo) << "platform " << platform;
      LOG(kInfo) << "current_platform " << current_platform;
      if (platform != current_platform)
        continue;

      std::string current_cpu_size(*(++it));
      LOG(kInfo) << "cpu_size " << cpu_size;
      LOG(kInfo) << "current_cpu_size " << current_cpu_size;
      if (cpu_size != current_cpu_size)
        continue;

      std::string temp_max_version = *(++it);
      std::string temp_max_patchlevel = *(++it);

      if (download_manager_.FileIsLaterThan((*dir_it).path().stem().string(), latest_file)) {
        latest_file = (*dir_it).path().stem().string();
        max_version = temp_max_version;
        max_patchlevel = temp_max_patchlevel;
      }
    }
    return std::pair<std::string, std::string>(max_version, max_patchlevel);
  }

  void VaultManager::ListenForUpdates() {
//     std::string name("lifestufflocal");
    int32_t cpu_size(maidsafe::CpuSize());
    std::string platform;
    std::string extension = "";

    std::string filetypes[] = {"lifestufflocal", "pd-vault"};
    std::vector<std::string> download_type(filetypes, filetypes + sizeof(filetypes)
                                                     / sizeof(std::string));
    std::vector<std::string>::iterator download_type_iterator = download_type.begin();

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
    while (true) {
      std::string name(*download_type_iterator);
      LOG(kInfo) << "Searching for latest local version of " << name;
      version_and_patchlevel = FindLatestLocalVersion(name, platform,
                                                      boost::lexical_cast<std::string>(cpu_size));
      std::string latest_local_file = name + "_" + platform + "_"
                                    + boost::lexical_cast<std::string>(cpu_size) + "_"
                                    + version_and_patchlevel.first + "_"
                                    + version_and_patchlevel.second + extension;
      LOG(kInfo) << "Cpu size: " << cpu_size;
      current_version = version_and_patchlevel.first;
      current_patchlevel = version_and_patchlevel.second;
      LOG(kInfo) << "Latest local version of " << name << " is "
                                              << version_and_patchlevel.first << "_"
                                              << version_and_patchlevel.second;
      download_manager_ = DownloadManager("dash.maidsafe.net", "~phil", name,
                                          platform, boost::lexical_cast<std::string>(cpu_size),
                                          current_version, current_patchlevel);

      LOG(kInfo) << "Initialise Download Manager";
      if (download_manager_.FindLatestFile()) {
        std::string file_to_download(download_manager_.file_to_download());

        // Download the signature file
        std::string signature_file = file_to_download + extension + ".sig";
        LOG(kInfo) << "Signature file is " << signature_file;
        download_manager_.SetFileToDownload(signature_file);

        if (download_manager_.UpdateCurrentFile(current_path)) {
          LOG(kInfo) << "Signature file " << signature_file << " has been downloaded!";
        } else {
          LOG(kInfo) << "ERROR!!! - signature file " << signature_file
                    << " has not been downloaded!!!";
        }

        // Download the client file
        file_to_download = file_to_download +  extension;
        LOG(kInfo) << "Client file is " << file_to_download;
        download_manager_.SetFileToDownload(file_to_download);

        if (download_manager_.UpdateCurrentFile(current_path)) {
          std::cout << "Client file " << file_to_download << " has been downloaded!" << std::endl;
        } else {
          LOG(kInfo) << "ERROR!!! - client file " << file_to_download
                    << " has not been downloaded!!!";
        }

        if (download_manager_.VerifySignature()) {
          // Remove the signature_file
          LOG(kInfo) << "Removing signature file";
          boost::filesystem::path symlink(current_path / name);
          boost::filesystem::remove(current_path / signature_file);
          boost::filesystem::remove(symlink);

          boost::filesystem::create_symlink(file_to_download, symlink);
          LOG(kInfo) << "Symbolic link " << symlink.string()
                     << " to the client file has been created!";

          // Remove the previous client file
          while (boost::filesystem::exists(current_path / latest_local_file)) {
            if (boost::filesystem::remove(current_path / latest_local_file)) {
              continue;
            }
            boost::this_thread::sleep(boost::posix_time::minutes(2));
          }

        } else {
          LOG(kInfo) << "Removing downloaded files";
          // Remove the signature_file
          boost::filesystem::remove(current_path / signature_file);
          boost::filesystem::remove(current_path / file_to_download);
        }
      } else {
        LOG(kInfo) << "No later file has been found!!!";
      }

      if (download_type_iterator !=download_type.end()) {
        ++download_type_iterator;
        continue;
      } else {
        download_type_iterator = download_type.begin();
        LOG(kInfo) << "Sleeping for five minutes!";
        boost::this_thread::sleep(boost::posix_time::minutes(5));
      }
    }
  }

  void VaultManager::ListenForMessages() {
    while (transport_->StartListening(Endpoint(boost::asio::ip::address_v4::loopback(),
        local_port_)) != kSuccess) {
      ++local_port_;
      if (local_port_ > 6483) {
        std::cout << "ListenForMessages: Listening failed on all ports in range" << std::endl;
        return;
      }
    }
    std::cout << "ListenForMessages: Listening on: " << local_port_ << std::endl;
    for (;;) {}
  }

  void VaultManager::OnError(const TransportCondition &transport_condition,
                             const Endpoint &/*remote_endpoint*/) {
    std::cout << "Error " << transport_condition << "sending message." << std::endl;
  }

  void VaultManager::HandleIncomingMessage(const int& type, const std::string& payload,
                                    const Info& info, std::string* response) {
    std::cout << "HandleIncomingMessage: message type " << type << " received." << std::endl;
    VaultManagerMessageType message_type = boost::numeric_cast<VaultManagerMessageType>(type);
    switch (message_type) {
      case VaultManagerMessageType::kHelloFromClient:
        std::cout << "kHelloFromClient" << std::endl;
        HandleClientHello(payload, info, response);
        break;
      case VaultManagerMessageType::kIdentityInfoRequestFromVault:
        std::cout << "kIndentityInfoRequestFromVault" << std::endl;
        HandleVaultInfoRequest(payload, info, response);
        break;
      case VaultManagerMessageType::kStartRequestFromClient:
        std::cout << "kStartRequestFromClient" << std::endl;
        HandleClientStartVaultRequest(payload, info, response);
        break;
      default:
        std::cout << "Incorrect message type" << std::endl;
    }
  }

  void VaultManager::HandleClientHello(const std::string& hello_string, const Info& info,
                                       std::string* response) {
    ClientHello hello;
    if (hello.ParseFromString(hello_string)) {
      if (hello.hello() == "hello") {
        Endpoint return_endpoint(info.endpoint.ip, info.endpoint.port);
        int message_type(static_cast<int>(VaultManagerMessageType::kHelloResponseToClient));
        ClientHelloResponse hello_response;
        hello_response.set_hello_response("hello response");
        *response = msg_handler_.MakeSerialisedWrapperMessage(message_type,
                                                              hello_response.SerializeAsString());
        return;
      }
    }
    std::cout << "HandleClientHello: Problem parsing client's hello message" << std::endl;
  }

  void VaultManager::HandleClientStartVaultRequest(const std::string& start_vault_string,
                                                   const Info& /*info*/, std::string* response) {
    std::cout << "HandleClientStartVaultRequest" << std::endl;
    ClientStartVaultRequest request;
    if (request.ParseFromString(start_vault_string)) {
      asymm::Keys keys;
      asymm::ParseKeys(request.keys(), keys);
      std::cout << "VaultManager: Identity: " << (keys.identity) << std::endl;
      std::cout << "Validation Token: " << (keys.validation_token) << std::endl;
      std::string public_key_string;
      maidsafe::asymm::EncodePublicKey(keys.public_key, &public_key_string);
      std::string private_key_string;
      maidsafe::asymm::EncodePrivateKey(keys.private_key, &private_key_string);
      std::cout << "Public Key: " << maidsafe::Base64Substr(public_key_string) << std::endl;
      std::cout << "Private Key: " << maidsafe::Base64Substr(private_key_string) << std::endl;
      std::string account_name(request.account_name());
      std::cout << "Account name: " << account_name << std::endl;
      std::string vmid;
      std::string chunkstore_path = (GetSystemAppDir()/"TestVault").string()
                                      + RandomAlphaNumericString(5) + "/";
      vmid = RunVault(chunkstore_path, "0", true);
      std::shared_ptr<WaitingVaultInfo> current_vault_info(new WaitingVaultInfo());
      current_vault_info->vault_vmid = vmid;
      std::cout << "Client request: Vault vmid: " << vmid << std::endl;
      /*current_vault_info.client_endpoint = return_endpoint;*/
      current_vault_info->account_name = account_name;
      current_vault_info->keys = keys;
      current_vault_info->chunkstore_path = chunkstore_path;
      current_vault_info->chunkstore_capacity = "0";
      std::cout << "Client request: struct address: " << current_vault_info << std::endl;
      client_started_vault_vmids_.push_back(current_vault_info);

      boost::mutex::scoped_lock lock(current_vault_info->mutex_);
      std::cout << "HandleClientStartVaultRequest: waiting for Vault" << std::endl;
      if (current_vault_info->cond_var_.timed_wait(lock,
                             boost::posix_time::seconds(3),
                             [&]()->bool { return current_vault_info->vault_requested_; })) {  // NOLINT (Philip)
        // SEND RESPONSE TO CLIENT
        ClientStartVaultResponse start_vault_response;
        start_vault_response.set_result(true);
        int message_type(static_cast<int>(VaultManagerMessageType::kStartResponseToClient));
        *response = msg_handler_.MakeSerialisedWrapperMessage(
            message_type, start_vault_response.SerializeAsString());
        std::cout << "HandleClientStartVaultRequest: wait for Vault succeeded" << std::endl;
        return;
      }
      std::cout << "HandleClientStartVaultRequest: wait for Vault timed out" << std::endl;
    } else {
    std::cout << "HandleClientStartVaultRequest: Problem parsing client's start vault message"
              << std::endl;
    }
  }

  void VaultManager::HandleVaultInfoRequest(const std::string& vault_info_request_string,
                                            const Info& /*info*/, std::string* vault_info_string) {
     std::cout << "HandleVaultInfoRequest" << std::endl;
     // GET INFO REQUEST
     VaultIdentityRequest request;
     bool new_vault(false);
     auto client_it(client_started_vault_vmids_.begin());
     auto config_it(config_file_vault_vmids_.begin());
     if (request.ParseFromString(vault_info_request_string)) {
       std::string vmid(request.vmid());
       std::cout << "Vault request: Vault vmid: " << vmid << std::endl;
       for (; client_it != client_started_vault_vmids_.end(); ++client_it) {
         if ((*client_it)->vault_vmid == vmid) {
           new_vault = true;
           std::cout << "Found ID in client_started_vault_vmids_" << std::endl;
           break;
         }
       }
       if (!new_vault) {
         for (; config_it != config_file_vault_vmids_.end(); ++config_it) {
           if ((*config_it)->vault_vmid == vmid) {
             break;
           }
         }
       }
     }
    // SEND INFO TO VAULT
    VaultIdentityInfo vault_info;
    std::string keys_string;
    std::shared_ptr<WaitingVaultInfo> waiting_vault_info(new_vault ? *client_it : *config_it);

    vault_info.set_account_name(waiting_vault_info->account_name);
    asymm::SerialiseKeys(waiting_vault_info->keys, keys_string);
    vault_info.set_keys(keys_string);

    int message_type(static_cast<int>(VaultManagerMessageType::kIdentityInfoToVault));
    *vault_info_string = msg_handler_.MakeSerialisedWrapperMessage(message_type,
                                                                   vault_info.SerializeAsString());
    boost::mutex::scoped_lock lock(waiting_vault_info->mutex_);
    waiting_vault_info->vault_requested_ = true;
    waiting_vault_info->cond_var_.notify_all();
    std::cout << "Vault request: struct address: " << waiting_vault_info << std::endl;
    std::cout << "HandleVaultInfoRequest: notify all called" << std::endl;
  }

  void VaultManager::StartListening() {
     transport_->on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                          &msg_handler_, _1, _2, _3, _4));
    transport_->on_error()->connect(boost::bind(&MessageHandler::OnError,
                                               &msg_handler_, _1, _2));
    msg_handler_.on_error()->connect(boost::bind(&VaultManager::OnError, this, _1, _2));
    msg_handler_.SetCallback(boost::bind(&VaultManager::HandleIncomingMessage, this, _1, _2, _3,
                                         _4));
    std::string request;

    /*boost::thread updates_thread( [&] { ListenForUpdates(); } ); // NOLINT
    if (updates_thread.joinable())
      updates_thread.join();*/

    boost::thread mediator_thread( [&] { ListenForMessages(); } ); // NOLINT
    if (mediator_thread.joinable())
      mediator_thread.join();
    transport_->StopListening();
  }
}       // namespace priv
}       // namespace maidsafe
