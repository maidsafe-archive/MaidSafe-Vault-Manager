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

#include "maidsafe/vault_manager/tools/actions/start_network.h"

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

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

namespace {

void StartZeroStateRoutingNodes(LocalNetworkController* local_network_controller,
                                std::promise<void>& zero_state_nodes_started,
                                std::future<void> finished_with_zero_state_nodes) {
  try {
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
        [&] { return node0->ZeroStateJoin(functors0, contact0, contact1, node_info1); }));
    auto join_future1(std::async(std::launch::async,
        [&] { return node1->ZeroStateJoin(functors1, contact1, contact0, node_info0); }));
    if (join_future0.get() != 0 || join_future1.get() != 0) {
      TLOG(kRed) << "Could not start zero state routing nodes.\n";
      BOOST_THROW_EXCEPTION(MakeError(RoutingErrors::not_connected));
    }

    routing::WriteBootstrapFile(routing::BootstrapContacts{ contact0, contact1 },
                                local_network_controller->test_env_root_dir / kBootstrapFilename);
    zero_state_nodes_started.set_value();

    finished_with_zero_state_nodes.get();
    TLOG(kDefaultColour) << "Shutting down zero state routing nodes\n";
  }
  catch (const std::exception&) {
    zero_state_nodes_started.set_exception(std::current_exception());
  }
}

void StartVaultManagerAndClientInterface(LocalNetworkController* local_network_controller) {
  TLOG(kDefaultColour) << "Creating VaultManager and ClientInterface\n";
  local_network_controller->vault_manager = maidsafe::make_unique<VaultManager>();
  passport::MaidAndSigner maid_and_signer{ passport::CreateMaidAndSigner() };
  local_network_controller->client_interface =
      maidsafe::make_unique<ClientInterface>(maid_and_signer.first);
}

void StartFirstTwoVaults(LocalNetworkController* local_network_controller, DiskUsage max_usage) {
  TLOG(kDefaultColour) << "Starting vault 1\n";  // index 2 in pmid list
  std::string vault_dir_name{ DebugId(GetPmidAndSigner(2).first.name().value) };
  fs::create_directories(local_network_controller->test_env_root_dir / vault_dir_name);
  auto first_vault_future(local_network_controller->client_interface->StartVault(
      local_network_controller->test_env_root_dir / vault_dir_name, max_usage, 2));
  try {
    first_vault_future.get();
  }
  catch (const std::exception& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
  }
  Sleep(std::chrono::milliseconds(500));

  TLOG(kDefaultColour) << "Starting vault 2\n";  // index 3 in pmid list
  vault_dir_name = DebugId(GetPmidAndSigner(3).first.name().value);
  fs::create_directories(local_network_controller->test_env_root_dir / vault_dir_name);
  auto second_vault_future(local_network_controller->client_interface->StartVault(
      local_network_controller->test_env_root_dir / vault_dir_name, max_usage, 3));
  try {
    second_vault_future.get();
  }
  catch (const std::exception& e) {
    LOG(kWarning) << boost::diagnostic_information(e);
  }
  Sleep(std::chrono::milliseconds(500));
}

void StartRemainingVaults(LocalNetworkController* local_network_controller, DiskUsage max_usage) {
  const int kRemainingIndex(local_network_controller->vault_count + 2);
  for (int i(4); i < kRemainingIndex; ++i) {
    TLOG(kDefaultColour) << "Starting vault " << i - 1 << '\n';  // index i in pmid list
    std::string vault_dir_name{ DebugId(GetPmidAndSigner(i).first.name().value) };
    fs::create_directories(local_network_controller->test_env_root_dir / vault_dir_name);
    auto vault_future(local_network_controller->client_interface->StartVault(
        local_network_controller->test_env_root_dir / vault_dir_name, max_usage, i));
    vault_future.get();
    Sleep(std::chrono::milliseconds(500));
  }
}

}  // unnamed namespace

void StartNetwork(LocalNetworkController* local_network_controller) {
  TLOG(kDefaultColour) << "\nCreating " << local_network_controller->vault_count
                       << " sets of Pmid keys (this may take a while)\n";
  ClientInterface::SetTestEnvironment(
      static_cast<Port>(local_network_controller->vault_manager_port),
      local_network_controller->test_env_root_dir, local_network_controller->path_to_vault,
      routing::BootstrapContact{}, local_network_controller->vault_count + 2);

  auto space_info(fs::space(local_network_controller->test_env_root_dir));
  DiskUsage max_usage{ (9 * space_info.available) / (10 * local_network_controller->vault_count) };
  std::promise<void> zero_state_nodes_started, finished_with_zero_state_nodes;
  std::thread zero_state_launcher;
  try {
    zero_state_launcher = std::move(std::thread{
        [&] { StartZeroStateRoutingNodes(local_network_controller, zero_state_nodes_started,
                                         finished_with_zero_state_nodes.get_future());
            } });
    zero_state_nodes_started.get_future().get();

    StartVaultManagerAndClientInterface(local_network_controller);
    StartFirstTwoVaults(local_network_controller, max_usage);

    finished_with_zero_state_nodes.set_value();
    zero_state_launcher.join();
  }
  catch (const std::exception&) {
    finished_with_zero_state_nodes.set_value();
    zero_state_launcher.join();
    throw;
  }
  Sleep(std::chrono::seconds(2));

  routing::WriteBootstrapFile(
      routing::BootstrapContacts{ 1, routing::BootstrapContact{ GetLocalIp(), kLivePort } },
      local_network_controller->test_env_root_dir / kBootstrapFilename);

  StartRemainingVaults(local_network_controller, max_usage);
  Sleep(std::chrono::milliseconds(500));

  TLOG(kGreen)
      << "Network setup completed successfully.\n"
      << "To keep the network alive or stay connected to VaultManager, do not exit this tool.\n";
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
