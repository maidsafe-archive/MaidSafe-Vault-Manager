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

#include "maidsafe/vault_manager/tools/commands/choose_vault_count.h"

#include <limits>
#include <memory>
#include <string>
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

ChooseVaultCount::ChooseVaultCount(LocalNetworkController* local_network_controller)
    : Command(local_network_controller, "Number of Vaults to start.",
              "\nThis must be at least 10.\nThere is no upper limit, but more than 20 on one PC "
              "will probably\ncause noticeable performance slowdown.  'Enter' to use default " +
              std::to_string(GetDefault().kVaultCount) + '\n' + kPrompt_),
      zero_state_nodes_started_(),
      finished_with_zero_state_nodes_() {}

void ChooseVaultCount::GetChoice() {
  TLOG(kDefaultColour) << kInstructions_;
  while (!DoGetChoice(local_network_controller_->vault_count, &GetDefault().kVaultCount, 10,
                      std::numeric_limits<int>::max())) {
    TLOG(kDefaultColour) << '\n' << kInstructions_;
  }
}

void ChooseVaultCount::HandleChoice() {
  TLOG(kDefaultColour) << "\nCreating " << local_network_controller_->vault_count
                       << " sets of Pmid keys (this may take a while)\n";
  ClientInterface::SetTestEnvironment(
      static_cast<Port>(local_network_controller_->vault_manager_port),
      local_network_controller_->test_env_root_dir, local_network_controller_->path_to_vault,
      routing::BootstrapContact{}, local_network_controller_->vault_count + 2);
  std::thread zero_state_launcher{ [&] { StartZeroStateRoutingNodes(); } };
  zero_state_nodes_started_.get_future().get();

  StartVaultManagerAndClientInterface();
  StartFirstTwoVaults();

  finished_with_zero_state_nodes_.set_value();
  zero_state_launcher.join();
  Sleep(std::chrono::seconds(10));

  routing::WriteBootstrapFile(
      routing::BootstrapContacts{ 1, routing::BootstrapContact{ GetLocalIp(), kLivePort} },
      local_network_controller_->test_env_root_dir / kBootstrapFilename);

  StartRemainingVaults();

  local_network_controller_->current_command =
      maidsafe::make_unique<ChooseTest>(local_network_controller_);

  TLOG(kGreen)
      << "Network setup completed successfully.\n"
      << "To keep the network alive or stay connected to VaultManager, do not exit this tool.\n";
  TLOG(kDefaultColour) << kSeparator_;
}

void ChooseVaultCount::StartZeroStateRoutingNodes() {
  TLOG(kDefaultColour) << "Creating two zero state routing nodes\n";
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
    TLOG(kRed) << "Could not start zero state routing nodes.\n";
    BOOST_THROW_EXCEPTION(MakeError(RoutingErrors::not_connected));
  }

  routing::WriteBootstrapFile(routing::BootstrapContacts{ contact0, contact1 },
                              local_network_controller_->test_env_root_dir / kBootstrapFilename);
  zero_state_nodes_started_.set_value();

  finished_with_zero_state_nodes_.get_future().get();
  TLOG(kDefaultColour) << "Shutting down zero state routing nodes\n";
}

void ChooseVaultCount::StartVaultManagerAndClientInterface() {
  TLOG(kDefaultColour) << "Creating VaultManager and ClientInterface\n";
  local_network_controller_->vault_manager = maidsafe::make_unique<VaultManager>();
  passport::MaidAndSigner maid_and_signer{ passport::CreateMaidAndSigner() };
  local_network_controller_->client_interface =
      maidsafe::make_unique<ClientInterface>(maid_and_signer.first);
}

void ChooseVaultCount::StartFirstTwoVaults() {
  TLOG(kDefaultColour) << "Starting vault 1\n";  // index 2 in pmid list
  std::string vault_dir_name{ DebugId(GetPmidAndSigner(2).first.name().value) };
  fs::create_directories(local_network_controller_->test_env_root_dir / vault_dir_name);
  // TODO(Fraser#5#): 2014-05-19 - BEFORE_RELEASE handle size properly.
  auto first_vault_future(local_network_controller_->client_interface->StartVault(
      local_network_controller_->test_env_root_dir / vault_dir_name, DiskUsage{ 10000000000 }, 2));
  try {
    first_vault_future.get();
  }
  catch (const std::exception& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
  }
  Sleep(std::chrono::seconds(2));

  TLOG(kDefaultColour) << "Starting vault 2\n";  // index 3 in pmid list
  vault_dir_name = DebugId(GetPmidAndSigner(3).first.name().value);
  fs::create_directories(local_network_controller_->test_env_root_dir / vault_dir_name);
  // TODO(Fraser#5#): 2014-05-19 - BEFORE_RELEASE handle size properly.
  auto second_vault_future(local_network_controller_->client_interface->StartVault(
      local_network_controller_->test_env_root_dir / vault_dir_name, DiskUsage{ 10000000000 }, 3));
  try {
    second_vault_future.get();
  }
  catch (const std::exception& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
  }
  Sleep(std::chrono::seconds(2));
}

void ChooseVaultCount::StartRemainingVaults() {
  for (int i(4); i < local_network_controller_->vault_count + 2; ++i) {
    TLOG(kDefaultColour) << "Starting vault " << i - 1 << '\n';  // index i in pmid list
    std::string vault_dir_name{ DebugId(GetPmidAndSigner(i).first.name().value) };
    fs::create_directories(local_network_controller_->test_env_root_dir / vault_dir_name);
    // TODO(Fraser#5#): 2014-05-19 - BEFORE_RELEASE handle size properly.
    auto vault_future(local_network_controller_->client_interface->StartVault(
      local_network_controller_->test_env_root_dir / vault_dir_name, DiskUsage{ 10000000000 }, i));
    vault_future.get();
    Sleep(std::chrono::seconds(2));
  }
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
