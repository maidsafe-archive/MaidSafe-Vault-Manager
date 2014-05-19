/*  Copyright 2014 MaidSafe.net limited

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

#include "maidsafe/vault_manager/tools/commands/start_network.h"

#include <memory>
#include <thread>

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/common/process.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/routing/bootstrap_file_operations.h"
#include "maidsafe/routing/routing_api.h"
#include "maidsafe/routing/node_info.h"
#include "maidsafe/nfs/utils.h"
#include "maidsafe/nfs/client/data_getter.h"

#include "maidsafe/vault_manager/client_interface.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_manager.h"
#include "maidsafe/vault_manager/tools/local_network_controller.h"
#include "maidsafe/vault_manager/tools/commands/choose_test.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

StartNetwork::StartNetwork(LocalNetworkController* local_network_controller)
    : Command(local_network_controller, "Start Network"),
      test_env_root_dir_(),
      path_to_vault_(),
      vault_manager_port_(0),
      vault_count_(0),
      kDefaultTestEnvRootDir_(fs::temp_directory_path() / "MaidSafe_TestNetwork"),
      kDefaultPathToVault_(process::GetOtherExecutablePath(fs::path{ "vault" })),
      kDefaultVaultManagerPort_(44444),
      kDefaultVaultCount_(12),
      finished_with_zero_state_nodes_() {}

void StartNetwork::PrintOptions() const {
  boost::system::error_code ec;
  if (test_env_root_dir_.empty()) {
    TLOG(kDefaultColour)
        << "Enter VaultManager root directory.  Hit enter to use default\n"
        << kDefaultTestEnvRootDir_ << '\n' << kDefaultOutput_;
  } else if (!fs::exists(test_env_root_dir_, ec) || ec) {
    TLOG(kDefaultColour)
        << "Do you wish to create " << test_env_root_dir_ << "?\nEnter 'y' or 'n'.\n"
        << kDefaultOutput_;
  } else if (path_to_vault_.empty()) {
    TLOG(kDefaultColour)
        << "Enter path to Vault executable.  Hit enter to use default\n"
        << kDefaultPathToVault_ << '\n' << kDefaultOutput_;
  } else if (vault_manager_port_ == 0) {
    TLOG(kDefaultColour)
        << "Enter preferred VaultManager listening port.  This should be between\n"
        << "1025 and 65536 inclusive.  Hit enter to use default " << kDefaultVaultManagerPort_
        << '\n' << kDefaultOutput_;
  } else {
    TLOG(kDefaultColour)
        << "Enter number of Vaults to start.  This must be at least 10.\nThere is no "
        << "upper limit, but more than 20 on one PC will probably\ncause noticeable "
        << "performance slowdown.  Hit enter to use default " << kDefaultVaultCount_ << '\n'
        << kDefaultOutput_;
  }
}

void StartNetwork::GetChoice() {
  for (;;) {
    while (!GetPathChoice(test_env_root_dir_, &kDefaultTestEnvRootDir_, false)) {
      TLOG(kDefaultColour) << '\n';
      PrintOptions();
    }
    boost::system::error_code ec;
    if (fs::exists(test_env_root_dir_, ec))
      break;

    PrintOptions();
    bool create;
    while (!GetBoolChoice(create, nullptr)) {
      TLOG(kDefaultColour) << '\n';
      PrintOptions();
    }
    if (create) {
      if (fs::create_directories(test_env_root_dir_, ec))
        break;
    }
  }

  PrintOptions();
  while (!GetPathChoice(path_to_vault_, &kDefaultPathToVault_, true)) {
    TLOG(kDefaultColour) << '\n';
    PrintOptions();
  }

  PrintOptions();
  while (!GetIntChoice(vault_manager_port_, &kDefaultVaultManagerPort_, 1025, 65536)) {
    TLOG(kDefaultColour) << '\n';
    PrintOptions();
  }

  PrintOptions();
  while (!GetIntChoice(vault_count_, &kDefaultVaultCount_, 10)) {
    TLOG(kDefaultColour) << '\n';
    PrintOptions();
  }
}

void StartNetwork::HandleChoice() {
  if (exit_) {
    local_network_controller_->current_command.reset();
    return;
  }
  TLOG(kDefaultColour) << "Creating " << vault_count_ + 2 << " sets of Pmid keys...\n";
  ClientInterface::SetTestEnvironment(static_cast<Port>(vault_manager_port_), test_env_root_dir_,
                                      path_to_vault_, routing::BootstrapContact{}, vault_count_);
  std::thread zero_state_launcher{ [&] { StartZeroStateRoutingNodes(); } };
  zero_state_nodes_started_.get_future().get();

  StartVaultManagerAndClientInterface();
  TakeOwnershipOfFirstVault();
  StartSecondVault();

  TLOG(kDefaultColour) << "Killing zero state nodes and waiting for network to stabilise...\n";
  finished_with_zero_state_nodes_.set_value();
  zero_state_launcher.join();
  Sleep(std::chrono::seconds(10));

  routing::WriteBootstrapFile(
      routing::BootstrapContacts{ 1, routing::BootstrapContact{ GetLocalIp(), kLivePort} },
      test_env_root_dir_ / kBootstrapFilename);

  StartRemainingVaults();

  local_network_controller_->current_command =
      maidsafe::make_unique<ChooseTest>(local_network_controller_);
}

void StartNetwork::StartZeroStateRoutingNodes() {
  TLOG(kDefaultColour) << "Creating zero state routing network...\n";
  AsioService asio_service{ 1 };
  std::unique_ptr<routing::Routing> node0{
      maidsafe::make_unique<routing::Routing>(GetPmidAndSigner(0).first) };
  routing::NodeInfo node_info0;
  node_info0.node_id = NodeId{ GetPmidAndSigner(0).first.name()->string() };
  node_info0.public_key = GetPmidAndSigner(0).first.public_key();

  std::unique_ptr<routing::Routing> node1{
      maidsafe::make_unique<routing::Routing>(GetPmidAndSigner(1).first) };
  routing::NodeInfo node_info1;
  node_info1.node_id = NodeId{ GetPmidAndSigner(1).first.name()->string() };
  node_info1.public_key = GetPmidAndSigner(1).first.public_key();

  nfs_client::DataGetter public_key_getter{ asio_service, *node0 };

  routing::Functors functors0, functors1;
  nfs::detail::PublicPmidHelper public_pmid_helper;
  functors0.request_public_key = functors1.request_public_key =
     [&](NodeId node_id, const routing::GivePublicKeyFunctor& give_key) {
    auto public_pmids(GetPublicPmids());
    nfs::detail::DoGetPublicKey(public_key_getter, node_id, give_key, public_pmids,
                                public_pmid_helper);
  };
  functors0.typed_message_and_caching.group_to_group.message_received =
      functors1.typed_message_and_caching.group_to_group.message_received =
          [&](const routing::GroupToGroupMessage&) {};
  functors0.typed_message_and_caching.group_to_single.message_received =
      functors1.typed_message_and_caching.group_to_single.message_received =
          [&](const routing::GroupToSingleMessage&) {};
  functors0.typed_message_and_caching.single_to_group.message_received =
      functors1.typed_message_and_caching.single_to_group.message_received =
          [&](const routing::SingleToGroupMessage&) {};
  functors0.typed_message_and_caching.single_to_single.message_received =
      functors1.typed_message_and_caching.single_to_single.message_received =
          [&](const routing::SingleToSingleMessage&) {};
  functors0.typed_message_and_caching.single_to_group_relay.message_received =
      functors1.typed_message_and_caching.single_to_group_relay.message_received =
          [&](const routing::SingleToGroupRelayMessage&) {};

  routing::BootstrapContact contact0{ GetLocalIp(), maidsafe::test::GetRandomPort() };
  routing::BootstrapContact contact1{ GetLocalIp(), maidsafe::test::GetRandomPort() };
  auto join_future0(std::async(std::launch::async,
      [&, this] { return node0->ZeroStateJoin(functors0, contact0, contact1, node_info1); }));
  auto join_future1(std::async(std::launch::async,
      [&, this] { return node1->ZeroStateJoin(functors1, contact1, contact0, node_info0); }));
  if (join_future0.get() != 0 || join_future1.get() != 0) {
    TLOG(kRed) << "Could not start zero state bootstrap nodes.\n";
    BOOST_THROW_EXCEPTION(MakeError(RoutingErrors::not_connected));
  }

  routing::WriteBootstrapFile(routing::BootstrapContacts{ contact0, contact1 },
                              test_env_root_dir_ / kBootstrapFilename);
  zero_state_nodes_started_.set_value();

  finished_with_zero_state_nodes_.get_future().get();
  TLOG(kDefaultColour) << "Shutting down zero state bootstrap nodes.\n";
}

void StartNetwork::StartVaultManagerAndClientInterface() {
  TLOG(kDefaultColour) << "Creating VaultManager and ClientInterface...\n";
  local_network_controller_->vault_manager = maidsafe::make_unique<VaultManager>();
  passport::MaidAndSigner maid_and_signer{ passport::CreateMaidAndSigner() };
  local_network_controller_->client_interface =
      maidsafe::make_unique<ClientInterface>(maid_and_signer.first);
}

void StartNetwork::TakeOwnershipOfFirstVault() {
  TLOG(kDefaultColour) << "Taking ownership of vault 0...\n";
  auto first_vault_future(local_network_controller_->client_interface->TakeOwnership(
      NonEmptyString{ "first vault" }, test_env_root_dir_ / kVaultDirname,
      DiskUsage{ 10000000000 }));
  first_vault_future.get();
  Sleep(std::chrono::seconds(2));
}

void StartNetwork::StartSecondVault() {
  TLOG(kDefaultColour) << "Starting vault 1...\n";
  // TODO(Fraser#5#): 2014-05-19 - BEFORE_RELEASE handle size properly.
  auto second_vault_future(local_network_controller_->client_interface->StartVault(
      test_env_root_dir_ / kVaultDirname, DiskUsage{ 10000000000 }, 3));
  second_vault_future.get();
  Sleep(std::chrono::seconds(2));
}

void StartNetwork::StartRemainingVaults() {
  for (int i(0); i < vault_count_; ++i) {
    TLOG(kDefaultColour) << "Starting vault " << i + 2 << "...\n";
    // TODO(Fraser#5#): 2014-05-19 - BEFORE_RELEASE handle size properly.
    auto vault_future(local_network_controller_->client_interface->StartVault(
       test_env_root_dir_ / kVaultDirname, DiskUsage{ 10000000000 }, i + 4));
    vault_future.get();
    Sleep(std::chrono::seconds(2));
  }
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
