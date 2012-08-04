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

#include <thread>
#include <iostream>
#include <string>
#include <vector>
#include "boost/tokenizer.hpp"
#include "boost/thread.hpp"
#include "boost/array.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"
#include "maidsafe/private/message_handler.h"
#include "maidsafe/private/vault_identity_info_pb.h"

namespace bai = boost::asio::ip;

namespace maidsafe {

namespace priv {

const uint16_t VaultManager::kMinPort(5483);
const uint16_t VaultManager::kMaxPort(5582);

VaultManager::VaultManager(const std::string &parent_path)
                        : vmid_vector_(),
                          process_vector_(),
                          manager_(),
                          download_manager_(),
                          asio_service_(new AsioService(3)),
                          msg_handler_(),
                          transport_(new TcpTransport(asio_service_->service())),
                          local_port_(kMinPort),
                          client_started_vault_vmids_(),
                          config_file_vault_vmids_(),
                          mediator_thread_(),
                          updates_thread_(),
                          mutex_(),
                          cond_var_(),
                          stop_listening_for_messages_(false),
                          stop_listening_for_updates_(false),
                          shutdown_requested_(false),
                          stopped_vaults_(0),
                          parent_path_(parent_path) {
  asio_service_->Start();
}

VaultManager::~VaultManager() {}

void VaultManager::RestartVaultManager(std::string latest_file, std::string executable_name) {
#ifdef WIN32
  std::string command("./restart_vm_windows.bat " + latest_file + " " + executable_name);
  system(command.c_str());
#else
  // system("/etc/init.d/mvm restart");
  std::string command("./restart_vm_linux.sh " + latest_file + " " + executable_name);
  system(command.c_str());
#endif
}

std::string VaultManager::RunVault(std::string chunkstore_path, std::string chunkstore_capacity,
                                   std::string bootstrap_endpoint) {
  maidsafe::Process process;
  LOG(kInfo) << "CREATING A VAULT at location: " << chunkstore_path << ", with capacity: "
             << chunkstore_capacity;
  if(parent_path_ != "") {
    process.SetProcessName("pd-vault", parent_path_);
    boost::filesystem::path exec_path(parent_path_);
    exec_path  /= "pd-vault";
    process.AddArgument(exec_path.string());
  } else {
    process.SetProcessName("pd-vault");
    process.AddArgument("pd-vault");
  }
  if (bootstrap_endpoint != "") {
    process.AddArgument("--peer");
    process.AddArgument(bootstrap_endpoint);
  }
  process.AddArgument("--chunk_path");
  process.AddArgument(chunkstore_path);
  process.AddArgument("--chunk_capacity");
  process.AddArgument(chunkstore_capacity);
  process.AddArgument("--start");
  LOG(kInfo) << "Process Name: " << process.ProcessName();

  /*process.SetProcessName("DUMMYprocess");
  process.AddArgument("DUMMYprocess");
  process.AddArgument("--nocrash");*/

  process_vector_.push_back(process);

  std::string vmid(manager_.AddProcess(process, local_port_));
  vmid_vector_.push_back(vmid);

  manager_.StartProcess(vmid);
  return vmid;
}

void VaultManager::RestartVault(std::string id) {
  manager_.RestartProcess(id);
}

void VaultManager::StopVault(int32_t id) {
//     manager_.KillProcess(vmid_vector_[id]);
  manager_.StopProcess(vmid_vector_[id]);
}

void VaultManager::EraseVault(int32_t id) {
    process_vector_.erase(process_vector_.begin() + (id - 1));
    manager_.KillProcess(vmid_vector_[id - 1]);
    vmid_vector_.erase(vmid_vector_.begin() + (id - 1));
    LOG(kInfo) << "Erasing vault...";
    if (WriteConfig()) {
      LOG(kInfo) << "Done!";
    }
}

bool VaultManager::WriteConfig() {
  std::vector<std::string> vault_info;
  fs::path path(/*GetSystemAppDir() / "vault_manager_config.txt"*/ "TestConfig.txt");
  std::string content, serialized_keys;

  for (size_t i = 0; i < config_file_vault_vmids_.size(); i++) {
    serialized_keys.clear();
    maidsafe::rsa::SerialiseKeys(config_file_vault_vmids_[i]->keys, serialized_keys);
    content += config_file_vault_vmids_[i]->chunkstore_path + " "
                + config_file_vault_vmids_[i]->chunkstore_capacity + " "
                + EncodeToBase32(serialized_keys) + " "
                + EncodeToBase32(config_file_vault_vmids_[i]->account_name)
                + "\n";
  }
  for (size_t i = 0; i < client_started_vault_vmids_.size(); i++) {
    serialized_keys.clear();
    maidsafe::rsa::SerialiseKeys(client_started_vault_vmids_[i]->keys, serialized_keys);
    content += client_started_vault_vmids_[i]->chunkstore_path + " "
                + client_started_vault_vmids_[i]->chunkstore_capacity + " "
                + EncodeToBase32(serialized_keys)
                + " " + EncodeToBase32(client_started_vault_vmids_[i]->account_name)
                + "\n";
  }
  return maidsafe::WriteFile(path, content);
}

bool VaultManager::ReadConfig() {
  fs::path path(/*GetSystemAppDir() / "vault_manager_config.txt"*/ "TestConfig.txt");
  if (path.parent_path() != "" && !fs::exists(path.parent_path())) {
    fs::create_directories(path.parent_path());
    return true;
  }
  if (!fs::exists(path))
    return true;
  std::string content;
  LOG(kInfo) << path.string();
  if (!maidsafe::ReadFile(path, &content)) {
    LOG(kError) << "ReadConfig: problem reading config file " << path;
    return false;
  }

  typedef boost::tokenizer<boost::char_separator<char> > vault_tokenizer;
  boost::char_separator<char> delimiter("\n");
  vault_tokenizer tok(content, delimiter);

  for (vault_tokenizer::iterator iterator = tok.begin(); iterator != tok.end(); ++iterator) {
    std::string argument = *iterator;

    typedef boost::tokenizer<boost::char_separator<char> > argument_tokenizer;
    boost::char_separator<char> argument_delimiter(" ", "", boost::keep_empty_tokens);
    argument_tokenizer arg_tokenizer(argument, argument_delimiter);
    std::vector<std::string> vault_item(arg_tokenizer.begin(), arg_tokenizer.end());
    LOG(kInfo) << "Location: " << vault_item[0];
    LOG(kInfo) << "Size: " << vault_item[1];
    LOG(kInfo) << "Serialized Keys: " << vault_item[2];
    LOG(kInfo) << "Account name: " << vault_item[3];

    asymm::Keys keys;
    if (!maidsafe::rsa::ParseKeys(DecodeFromBase32(vault_item[2]), keys))
      LOG(kInfo) << "Error parsing the keys!!!";

    std::shared_ptr<WaitingVaultInfo> vault_info(new WaitingVaultInfo());
    vault_info->keys = keys;
    vault_info->account_name = DecodeFromBase32(vault_item[3]);
    vault_info->chunkstore_path = vault_item[0];
    vault_info->chunkstore_capacity = vault_item[1];

    std::string vmid;
    vmid = RunVault(vault_item[0], vault_item[1]);

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
  LOG(kInfo) << "************************************************************";
  for (vault_tokenizer::iterator iterator = tok.begin(); iterator != tok.end(); ++iterator) {
    LOG(kInfo) << i << ". " << *iterator;
    i++;
  }
  LOG(kInfo) << "************************************************************";

  if (select) {
    int32_t option;
    LOG(kInfo) << "Select an item: ";
    std::cin >> option;
    return option;
  }

  return 0;
}

int32_t VaultManager::get_process_vector_size() {
  return static_cast<int32_t>(process_vector_.size());
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

  std::vector<std::string> download_type;
  download_type.push_back("lifestufflocal");
  download_type.push_back("pd-vault");
  std::vector<std::string>::iterator download_type_iterator = download_type.begin();

  #ifdef _WINDOWS
  platform = "win";
  extension = ".exe";
  #else
  #ifdef __APPLE__
  platform = "osx";
  #else
  platform = "linux";
  #endif
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
        LOG(kError) << "ERROR! - signature file " << signature_file
                  << " has not been downloaded!";
      }

      // Download the client file
      file_to_download = file_to_download +  extension;
      LOG(kInfo) << "Client file is " << file_to_download;
      download_manager_.SetFileToDownload(file_to_download);

      if (download_manager_.UpdateCurrentFile(current_path)) {
        LOG(kInfo) << "Client file " << file_to_download << " has been downloaded!";
      } else {
        LOG(kError) << "ERROR! - client file " << file_to_download << " has not been downloaded!";
      }

      if (download_manager_.VerifySignature()) {
        // Remove the signature_file
        LOG(kInfo) << "Removing signature file";
        boost::filesystem::remove(current_path / signature_file);
#ifndef WIN32
        boost::filesystem::path symlink(current_path / name);
        boost::filesystem::remove(symlink);

        boost::filesystem::create_symlink(file_to_download, symlink);
        LOG(kInfo) << "Symbolic link " << symlink.string()
                    << " to the client file has been created!";
#endif
        // Remove the previous client file
        while (boost::filesystem::exists(current_path / latest_local_file)) {
          if (boost::filesystem::remove(current_path / latest_local_file)) {
            continue;
          }
          boost::mutex::scoped_lock lock(mutex_);
          cond_var_.timed_wait(lock, boost::posix_time::minutes(2),
                                [&] { return stop_listening_for_updates_; });
          if (stop_listening_for_updates_)
            return;
        }
        if (name == "vault-manager" || name == "pd-vault")
          RestartVaultManager(file_to_download, name);
      } else {
        LOG(kInfo) << "Removing downloaded files";
        // Remove the signature_file
        boost::filesystem::remove(current_path / signature_file);
        boost::filesystem::remove(current_path / file_to_download);
      }
    } else {
      LOG(kInfo) << "No later file has been found!!!";
    }
    ++download_type_iterator;
    if (download_type_iterator != download_type.end()) {
      continue;
    } else {
      download_type_iterator = download_type.begin();
      LOG(kInfo) << "Sleeping for five minutes!";
      boost::mutex::scoped_lock lock(mutex_);
      cond_var_.timed_wait(lock, boost::posix_time::minutes(5),
                            [&] { return stop_listening_for_updates_; });
      if (stop_listening_for_updates_)
        return;
    }
  }
}

bool HandleBootstrapFile(asymm::Identity identity) {
  try {
    fs::path manager_bootstrap_path(GetSystemAppDir() / "bootstrap-global.dat");
    if (!fs::exists(manager_bootstrap_path)) {
      LOG(kError) << "Error: Main bootstrap file doesn't exist at " << manager_bootstrap_path;
      return false;
    }
    fs::path vault_bootstrap_path(GetSystemAppDir() / ("bootstrap-" + EncodeToBase32(identity) + ".dat"));
    if (!fs::exists(vault_bootstrap_path)) {
      fs::copy_file(manager_bootstrap_path, vault_bootstrap_path);
      // SET PERMISSIONS
    }
    return true;
  } catch(const std::exception& e) {
    LOG(kError) << "Error creating/accessing bootstrap file: " << e.what();
    // return false;
  }
  return false;
}

void VaultManager::ListenForMessages() {
  boost::mutex::scoped_lock lock(mutex_);
  while (transport_->StartListening(Endpoint(boost::asio::ip::address_v4::loopback(),
      local_port_)) != kSuccess) {
    ++local_port_;
    if (local_port_ > kMaxPort) {
      LOG(kError) << "ListenForMessages: Listening failed on all ports in range " << kMinPort
                  << " to " << kMaxPort;
      return;
    }
  }
  LOG(kInfo) << "ListenForMessages: Listening on port " << local_port_;
  cond_var_.wait(lock, [&]{ return shutdown_requested_; });  // NOLINT
  cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                        [&]{ return manager_.NumberOfLiveProcesses() == 0; });  // NOLINT
  LOG(kInfo) << "ListenForMessages: FINISHED Listening on port " << local_port_;
}

void VaultManager::OnError(const TransportCondition &transport_condition,
                            const Endpoint &/*remote_endpoint*/) {
  LOG(kError) << "Error " << transport_condition << " when sending message.";
}

void VaultManager::HandleIncomingMessage(const int& type, const std::string& payload,
                                  const Info& info, std::string* response) {
  LOG(kInfo) << "HandleIncomingMessage: message type " << type << " received.";
  if (info.endpoint.ip.to_string() != "127.0.0.1") {
    LOG(kError) << "HandleIncomingMessage: message is not of local origin.";
    return;
  }
  VaultManagerMessageType message_type = boost::numeric_cast<VaultManagerMessageType>(type);
  switch (message_type) {
    case VaultManagerMessageType::kHelloFromClient:
      LOG(kInfo) << "kHelloFromClient";
      HandleClientHello(payload, info, response);
      break;
    case VaultManagerMessageType::kIdentityInfoRequestFromVault:
      LOG(kInfo) << "kIdentityInfoRequestFromVault";
      HandleVaultInfoRequest(payload, info, response);
      break;
    case VaultManagerMessageType::kStartRequestFromClient:
      LOG(kInfo) << "kStartRequestFromClient";
      HandleClientStartVaultRequest(payload, info, response);
      break;
    case VaultManagerMessageType::kShutdownRequestFromVault:
      LOG(kInfo) << "kShutdownRequestFromVault";
      HandleVaultShutdownRequest(payload, info, response);
      break;
    default:
      LOG(kError) << "Invalid message type";
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
  LOG(kError) <<  "HandleClientHello: Problem parsing client's hello message";
}

void VaultManager::HandleClientStartVaultRequest(const std::string& start_vault_string,
                                                  const Info& /*info*/, std::string* response) {
  ClientStartVaultRequest request;
  if (request.ParseFromString(start_vault_string)) {
    asymm::Keys keys;
    asymm::ParseKeys(request.keys(), keys);
    std::string account_name(request.account_name()), vmid;
    std::string chunkstore_path = (/*GetSystemAppDir() /*/ "TestVault")/*.string()*/
                                    + RandomAlphaNumericString(5) + "/";
    if (!HandleBootstrapFile(keys.identity)) {
      // LOG(kError) << "failed to set bootstrap file for vault " << keys.identity;
      // return;
    }
    std::shared_ptr<WaitingVaultInfo> current_vault_info(new WaitingVaultInfo());
    current_vault_info->account_name = account_name;
    current_vault_info->keys = keys;
    current_vault_info->chunkstore_path = chunkstore_path;
    current_vault_info->chunkstore_capacity = "0";
    client_started_vault_vmids_.push_back(current_vault_info);
    LOG(kInfo) << "HandleClientStartVaultRequest: bootstrap endpoint is " << request.bootstrap_endpoint();
    vmid = RunVault(current_vault_info->chunkstore_path,
                    current_vault_info->chunkstore_capacity, request.bootstrap_endpoint());
    current_vault_info->vault_vmid = vmid;
    WriteConfig();

    boost::mutex::scoped_lock lock(current_vault_info->mutex_);
    LOG(kInfo) << "HandleClientStartVaultRequest: waiting for Vault" << vmid;
    if (current_vault_info->cond_var_.timed_wait(lock,
                            boost::posix_time::seconds(3),
                            [&]()->bool { return current_vault_info->vault_requested_; })) {  // NOLINT (Philip)
      // SEND RESPONSE TO CLIENT
      ClientStartVaultResponse start_vault_response;
      start_vault_response.set_result(true);
      int message_type(static_cast<int>(VaultManagerMessageType::kStartResponseToClient));
      *response = msg_handler_.MakeSerialisedWrapperMessage(
          message_type, start_vault_response.SerializeAsString());
      return;
    }
    LOG(kError) << "HandleClientStartVaultRequest: wait for Vault timed out";
  } else {
    LOG(kError) << "HandleClientStartVaultRequest: Problem parsing client's start vault message";
  }
}

void VaultManager::HandleVaultInfoRequest(const std::string& vault_info_request_string,
                                          const Info& /*info*/,
                                          std::string* vault_info_string) {
    // GET INFO REQUEST
    VaultIdentityRequest request;
    bool new_vault(false);
    auto client_it(client_started_vault_vmids_.begin());
    auto config_it(config_file_vault_vmids_.begin());
    if (request.ParseFromString(vault_info_request_string)) {
      std::string vmid(request.vmid());
      for (; client_it != client_started_vault_vmids_.end(); ++client_it) {
        if ((*client_it)->vault_vmid == vmid) {
          new_vault = true;
          LOG(kInfo) << "HandleVaultInfoRequest: request is from vault recently started by client";
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
}

void VaultManager::HandleVaultShutdownRequest(const std::string& vault_shutdown_string,
                                              const Info& /*info*/,
                                              std::string* response) {
  LOG(kInfo) <<  "HandleVaultShutdownRequest";
  VaultShutdownRequest request;
  if (request.ParseFromString(vault_shutdown_string)) {
    int message_type(static_cast<int>(VaultManagerMessageType::kShutdownResponseToVault));
    VaultShutdownResponse shutdown_response;
    boost::mutex::scoped_lock lock(mutex_);
    shutdown_response.set_shutdown(shutdown_requested_);
    LOG(kInfo) <<  "HandleVaultShutdownRequest: shutdown requested"
                << std::boolalpha << shutdown_requested_;
    *response = msg_handler_.MakeSerialisedWrapperMessage(message_type,
                                                          shutdown_response.SerializeAsString());
    if (shutdown_requested_) {
      LOG(kInfo) << "Shutting down a vault.";
      ++stopped_vaults_;
      cond_var_.notify_all();
    }
    return;
  }
  LOG(kError) <<  "HandleVaultShutdownRequest: Problem parsing client's shutdown request";
}

void VaultManager::StartListening() {
  transport_->on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                        &msg_handler_, _1, _2, _3, _4));
  transport_->on_error()->connect(boost::bind(&MessageHandler::OnError,
                                              &msg_handler_, _1, _2));
  msg_handler_.on_error()->connect(boost::bind(&VaultManager::OnError, this, _1, _2));
  msg_handler_.SetCallback(boost::bind(&VaultManager::HandleIncomingMessage, this, _1, _2, _3,
                                        _4));
  /*updates_thread_ = boost::thread( [&] { ListenForUpdates(); } ); // NOLINT*/
  mediator_thread_ = boost::thread( [&] { ListenForMessages(); } ); // NOLINT
}

void VaultManager::StopListening() {
  LOG(kInfo) << "Starting VaultManager shutdown sequence.";
  manager_.LetAllProcessesDie();
  boost::mutex::scoped_lock lock(mutex_);
  stop_listening_for_updates_ = true;
  LOG(kInfo) << "VaultManager: setting shutdown_requested_ to true";
  shutdown_requested_ = true;
  cond_var_.notify_all();
  lock.unlock();
  if (mediator_thread_.joinable())
    mediator_thread_.join();
  LOG(kInfo) << "After VaultManager vaults shutdown";
  /*if (updates_thread_.joinable())
    updates_thread_.join();*/
  transport_->StopListening();
}

}  // namespace priv

}  // namespace maidsafe
