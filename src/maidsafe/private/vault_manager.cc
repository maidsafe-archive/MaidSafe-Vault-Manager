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

#include <iostream>

#include "boost/filesystem/path.hpp"
#include "boost/tokenizer.hpp"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"

#include "maidsafe/private/controller_messages_pb.h"
#include "maidsafe/private/tcp_transport.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

VaultManager::VaultManager(const std::string& parent_path)
    : processes_(),
      process_manager_(),
      download_manager_(),
      asio_service_(3),
      message_handler_(),
      transport_(new TcpTransport(asio_service_.service())),
      local_port_(kMinPort()),
      client_started_vault_manager_ids_(),
      config_file_vault_manager_ids_(),
      mediator_thread_(),
      updates_thread_(),
      mutex_(),
      cond_var_(),
      stop_listening_for_messages_(false),
      stop_listening_for_updates_(false),
      shutdown_requested_(false),
      stopped_vaults_(0),
      parent_path_(parent_path) {
  asio_service_.Start();
}

VaultManager::~VaultManager() {}

void VaultManager::RestartVaultManager(std::string latest_file, std::string executable_name) {
#ifdef MAIDSAFE_WIN32
  std::string command("./restart_vm_windows.bat " + latest_file + " " + executable_name);
#else
  std::string command("./restart_vm_linux.sh " + latest_file + " " + executable_name);
#endif
  // system("/etc/init.d/mvm restart");
  int result(system(command.c_str()));
  if (result != 0)
    LOG(kWarning) << "Result: " << result;
}

std::string VaultManager::RunVault(std::string chunkstore_path,
                                   std::string chunkstore_capacity,
                                   std::string bootstrap_endpoint) {
  Process process;
  LOG(kInfo) << "CREATING A VAULT at location: " << chunkstore_path << ", with capacity: "
             << chunkstore_capacity;
  if (!parent_path_.empty()) {
    process.SetProcessName("pd-vault", parent_path_);
    process.AddArgument((fs::path(parent_path_) / "pd-vault").string());
  } else {
    process.SetProcessName("pd-vault");
    process.AddArgument("pd-vault");
  }

  if (!bootstrap_endpoint.empty()) {
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

  std::string vault_manager_id(process_manager_.AddProcess(process, local_port_));
  processes_.push_back(std::make_pair(process, vault_manager_id));
  process_manager_.StartProcess(vault_manager_id);
  return vault_manager_id;
}

void VaultManager::RestartVault(std::string id) {
  process_manager_.RestartProcess(id);
}

void VaultManager::StopVault(int32_t index) {
  if (index < static_cast<int32_t>(processes_.size())) {
    process_manager_.StopProcess(processes_[index].second);
  } else {
    LOG(kError) << "Invalid index of " << index << " for processes container with size "
                << processes_.size();
  }
}

void VaultManager::EraseVault(int32_t index) {
  if (index < static_cast<int32_t>(processes_.size())) {
    auto itr(processes_.begin() + (index - 1));
    process_manager_.KillProcess((*itr).second);
    processes_.erase(itr);
    LOG(kInfo) << "Erasing vault...";
    if (WriteConfig()) {
      LOG(kInfo) << "Done!";
    }
  } else {
    LOG(kError) << "Invalid index of " << index << " for processes container with size "
                << processes_.size();
  }
}

bool VaultManager::WriteConfig() {
  std::vector<std::string> vault_info;
  fs::path path(/*GetSystemAppDir() / "vault_manager_config.txt"*/ "TestConfig.txt");
  std::string content, serialized_keys;

  for (size_t i = 0; i < config_file_vault_manager_ids_.size(); i++) {
    serialized_keys.clear();
    asymm::SerialiseKeys(config_file_vault_manager_ids_[i]->keys, serialized_keys);
    content += config_file_vault_manager_ids_[i]->chunkstore_path + " "
                + config_file_vault_manager_ids_[i]->chunkstore_capacity + " "
                + EncodeToBase32(serialized_keys) + " "
                + EncodeToBase32(config_file_vault_manager_ids_[i]->account_name)
                + "\n";
  }
  for (size_t i = 0; i < client_started_vault_manager_ids_.size(); i++) {
    serialized_keys.clear();
    asymm::SerialiseKeys(client_started_vault_manager_ids_[i]->keys, serialized_keys);
    content += client_started_vault_manager_ids_[i]->chunkstore_path + " "
                + client_started_vault_manager_ids_[i]->chunkstore_capacity + " "
                + EncodeToBase32(serialized_keys)
                + " " + EncodeToBase32(client_started_vault_manager_ids_[i]->account_name)
                + "\n";
  }
  return WriteFile(path, content);
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
  if (!ReadFile(path, &content)) {
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
    if (!asymm::ParseKeys(DecodeFromBase32(vault_item[2]), keys))
      LOG(kInfo) << "Error parsing the keys!!!";

    std::shared_ptr<WaitingVaultInfo> vault_info(new WaitingVaultInfo());
    vault_info->keys = keys;
    vault_info->account_name = DecodeFromBase32(vault_item[3]);
    vault_info->chunkstore_path = vault_item[0];
    vault_info->chunkstore_capacity = vault_item[1];

    vault_info->vault_manager_id = RunVault(vault_item[0], vault_item[1]);
    config_file_vault_manager_ids_.push_back(vault_info);
  }
  return true;
}

int32_t VaultManager::ListVaults(bool select) const {
  fs::path path((GetSystemAppDir() / "config.txt"));

  std::string content;
  ReadFile(path, &content);

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

std::pair<std::string, std::string> VaultManager::FindLatestLocalVersion(std::string name,
                                                                         std::string platform,
                                                                         std::string cpu_size) {
  fs::path current_path(fs::current_path());
  fs::directory_iterator end;
  std::string latest_file(name + "_" + platform + "_" + cpu_size + "_0_0");
  std::string max_version, max_patchlevel;
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
  int32_t cpu_size(CpuSize());
  std::string platform, extension;

  std::vector<std::string> download_type;
  download_type.push_back("lifestufflocal");
  download_type.push_back("pd-vault");
  std::vector<std::string>::iterator download_type_iterator = download_type.begin();

#if defined MAIDSAFE_WIN32
  platform = "win";
  extension = ".exe";
#elif defined MAIDSAFE_APPLE
  platform = "osx";
#else
  platform = "linux";
#endif
  std::string current_version, current_patchlevel;
  std::pair<std::string, std::string> version_and_patchlevel;
  fs::path current_path(fs::current_path());
  for (;;) {
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
        fs::remove(current_path / signature_file);
#ifndef WIN32
        fs::path symlink(current_path / name);
        fs::remove(symlink);

        fs::create_symlink(file_to_download, symlink);
        LOG(kInfo) << "Symbolic link " << symlink.string()
                    << " to the client file has been created!";
#endif
        // Remove the previous client file
        while (fs::exists(current_path / latest_local_file)) {
          if (fs::remove(current_path / latest_local_file)) {
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
        fs::remove(current_path / signature_file);
        fs::remove(current_path / file_to_download);
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
  std::string short_vault_id(maidsafe::EncodeToBase32(
      maidsafe::crypto::Hash<maidsafe::crypto::SHA1>(identity)));
  fs::path vault_bootstrap_path(
      maidsafe::GetSystemAppDir() / ("bootstrap-" + short_vault_id + ".dat"));

  // just create empty file, Routing will fall back to global bootstrap file
  if (!fs::exists(vault_bootstrap_path) && !maidsafe::WriteFile(vault_bootstrap_path, "")) {
    LOG(kError) << "HandleBootstrapFile: Could not create " << vault_bootstrap_path;
    return false;
  }

  // TODO(Phil) set permissions to give vault exclusive access

  return true;
}

void VaultManager::ListenForMessages() {
  boost::mutex::scoped_lock lock(mutex_);
  while (transport_->StartListening(Endpoint(boost::asio::ip::address_v4::loopback(),
      local_port_)) != kSuccess) {
    ++local_port_;
    if (local_port_ > kMaxPort()) {
      LOG(kError) << "ListenForMessages: Listening failed on all ports in range " << kMinPort()
                  << " to " << kMaxPort();
      return;
    }
  }
  LOG(kInfo) << "ListenForMessages: Listening on port " << local_port_;
  cond_var_.wait(lock, [&]{ return shutdown_requested_; });  // NOLINT
  cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                        [&]{ return process_manager_.NumberOfLiveProcesses() == 0; });  // NOLINT
  LOG(kInfo) << "ListenForMessages: FINISHED Listening on port " << local_port_;
}

void VaultManager::OnError(const TransportCondition& transport_condition,
                           const Endpoint& /*remote_endpoint*/) {
  LOG(kError) << "Error " << transport_condition << " when sending message.";
}

void VaultManager::HandleIncomingMessage(const int& type,
                                         const std::string& payload,
                                         const Info& info,
                                         std::string* response) {
  LOG(kVerbose) << "HandleIncomingMessage: message type " << type << " received.";
  if (!info.endpoint.ip.is_loopback()) {
    LOG(kError) << "HandleIncomingMessage: message is not of local origin.";
    return;
  }
  VaultManagerMessageType message_type = boost::numeric_cast<VaultManagerMessageType>(type);
  switch (message_type) {
    case VaultManagerMessageType::kHelloFromClient:
      LOG(kVerbose) << "kHelloFromClient";
      HandleClientHello(payload, info, response);
      break;
    case VaultManagerMessageType::kIdentityInfoRequestFromVault:
      LOG(kVerbose) << "kIdentityInfoRequestFromVault";
      HandleVaultInfoRequest(payload, info, response);
      break;
    case VaultManagerMessageType::kStartRequestFromClient:
      LOG(kVerbose) << "kStartRequestFromClient";
      HandleClientStartVaultRequest(payload, info, response);
      break;
    case VaultManagerMessageType::kShutdownRequestFromVault:
      LOG(kVerbose) << "kShutdownRequestFromVault";
      HandleVaultShutdownRequest(payload, info, response);
      break;
    default:
      LOG(kError) << "Invalid message type";
  }
}

void VaultManager::HandleClientHello(const std::string& hello_string,
                                     const Info& info,
                                     std::string* response) {
  protobuf::ClientHello hello;
  if (hello.ParseFromString(hello_string)) {
    if (hello.hello() == "hello") {
      Endpoint return_endpoint(info.endpoint.ip, info.endpoint.port);
      int message_type(static_cast<int>(VaultManagerMessageType::kHelloResponseToClient));
      protobuf::ClientHelloResponse hello_response;
      hello_response.set_hello_response("hello response");
      *response = message_handler_.MakeSerialisedWrapperMessage(message_type,
                                                                hello_response.SerializeAsString());
      return;
    }
  }
  LOG(kError) << "HandleClientHello: Problem parsing client's hello message";
}

void VaultManager::HandleClientStartVaultRequest(const std::string& start_vault_string,
                                                 const Info& /*info*/,
                                                 std::string* response) {
  protobuf::ClientStartVaultRequest request;
  if (request.ParseFromString(start_vault_string)) {
    std::shared_ptr<WaitingVaultInfo> current_vault_info(new WaitingVaultInfo);
    current_vault_info->account_name = request.account_name();
    asymm::ParseKeys(request.keys(), current_vault_info->keys);
    current_vault_info->chunkstore_path = (/*GetSystemAppDir() /*/ "TestVault")/*.string()*/ +
                                          RandomAlphaNumericString(5) + "/";
    if (!HandleBootstrapFile(current_vault_info->keys.identity)) {
      LOG(kError) << "Failed to set bootstrap file for vault "
                  << HexSubstr(current_vault_info->keys.identity);
      return;
    }
    current_vault_info->chunkstore_capacity = "0";
    client_started_vault_manager_ids_.push_back(current_vault_info);
    LOG(kInfo) << "HandleClientStartVaultRequest: bootstrap endpoint is "
               << request.bootstrap_endpoint();
    current_vault_info->vault_manager_id = RunVault(current_vault_info->chunkstore_path,
                                                    current_vault_info->chunkstore_capacity,
                                                    request.bootstrap_endpoint());
    if (!WriteConfig())
      LOG(kError) << "Failed to write config file.";

    boost::mutex::scoped_lock lock(current_vault_info->mutex);
    LOG(kInfo) << "HandleClientStartVaultRequest: waiting for Vault "
               << current_vault_info->vault_manager_id;
    if (current_vault_info->cond_var.timed_wait(
            lock,
            boost::posix_time::seconds(3),
            [&] { return current_vault_info->vault_requested; })) {  // NOLINT (Philip)
      // Send response to client
      protobuf::ClientStartVaultResponse start_vault_response;
      start_vault_response.set_result(true);
      int message_type(static_cast<int>(VaultManagerMessageType::kStartResponseToClient));
      *response = message_handler_.MakeSerialisedWrapperMessage(
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
  protobuf::VaultIdentityRequest request;
  bool new_vault(false);
  auto client_it(client_started_vault_manager_ids_.begin());
  auto config_it(config_file_vault_manager_ids_.begin());
  if (request.ParseFromString(vault_info_request_string)) {
    for (; client_it != client_started_vault_manager_ids_.end(); ++client_it) {
      if ((*client_it)->vault_manager_id == request.vault_manager_id()) {
        new_vault = true;
        LOG(kInfo) << "HandleVaultInfoRequest: request is from vault recently started by client";
        break;
      }
    }
    if (!new_vault) {
      for (; config_it != config_file_vault_manager_ids_.end(); ++config_it) {
        if ((*config_it)->vault_manager_id == request.vault_manager_id()) {
          break;
        }
      }
    }
  }

  // Send info to vault
  protobuf::VaultIdentityInfo vault_info;
  std::string keys_string;
  std::shared_ptr<WaitingVaultInfo> waiting_vault_info(new_vault ? *client_it : *config_it);

  vault_info.set_account_name(waiting_vault_info->account_name);
  asymm::SerialiseKeys(waiting_vault_info->keys, keys_string);
  vault_info.set_keys(keys_string);

  int message_type(static_cast<int>(VaultManagerMessageType::kIdentityInfoToVault));
  *vault_info_string = message_handler_.MakeSerialisedWrapperMessage(message_type,
                                                                  vault_info.SerializeAsString());
  boost::mutex::scoped_lock lock(waiting_vault_info->mutex);
  waiting_vault_info->vault_requested = true;
  waiting_vault_info->cond_var.notify_all();
}

void VaultManager::HandleVaultShutdownRequest(const std::string& vault_shutdown_string,
                                              const Info& /*info*/,
                                              std::string* response) {
  protobuf::VaultShutdownRequest request;
  if (request.ParseFromString(vault_shutdown_string)) {
    int message_type(static_cast<int>(VaultManagerMessageType::kShutdownResponseToVault));
    protobuf::VaultShutdownResponse shutdown_response;
    boost::mutex::scoped_lock lock(mutex_);
    shutdown_response.set_shutdown(shutdown_requested_);
    LOG(kVerbose) << "HandleVaultShutdownRequest: shutdown requested "
                  << std::boolalpha << shutdown_requested_;
    *response =
        message_handler_.MakeSerialisedWrapperMessage(message_type,
                                                      shutdown_response.SerializeAsString());
    if (shutdown_requested_) {
      LOG(kInfo) << "Shutting down a vault.";
      ++stopped_vaults_;
      cond_var_.notify_all();
    }
    return;
  }
  LOG(kError) << "HandleVaultShutdownRequest: Problem parsing client's shutdown request";
}

void VaultManager::StartListening() {
  transport_->on_message_received()->connect(boost::bind(&MessageHandler::OnMessageReceived,
                                                        &message_handler_, _1, _2, _3, _4));
  transport_->on_error()->connect(boost::bind(&MessageHandler::OnError, &message_handler_, _1, _2));
  message_handler_.on_error()->connect(boost::bind(&VaultManager::OnError, this, _1, _2));
  message_handler_.SetCallback(
      boost::bind(&VaultManager::HandleIncomingMessage, this, _1, _2, _3, _4));
  /*updates_thread_ = boost::thread( [&] { ListenForUpdates(); } ); // NOLINT*/
  mediator_thread_ = boost::thread( [&] { ListenForMessages(); } ); // NOLINT
}

void VaultManager::StopListening() {
  LOG(kInfo) << "Starting VaultManager shutdown sequence.";
  process_manager_.LetAllProcessesDie();
  {
    boost::mutex::scoped_lock lock(mutex_);
    stop_listening_for_updates_ = true;
    LOG(kInfo) << "VaultManager: setting shutdown_requested_ to true";
    shutdown_requested_ = true;
    cond_var_.notify_all();
  }
  if (mediator_thread_.joinable())
    mediator_thread_.join();
  LOG(kInfo) << "After VaultManager vaults shutdown";
  /*if (updates_thread_.joinable())
    updates_thread_.join();*/
  transport_->StopListening();
}

}  // namespace priv

}  // namespace maidsafe
