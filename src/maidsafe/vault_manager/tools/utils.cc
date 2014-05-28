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

#include "maidsafe/vault_manager/tools/utils.h"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/nfs/public_pmid_helper.h"

#include "maidsafe/vault_manager/client_interface.h"

namespace maidsafe {

namespace vault_manager {

namespace tools {

PublicPmidStorer::PublicPmidStorer(const std::vector<passport::PublicPmid>& public_pmids)
    : asio_service_(2),
      kMaidAndSigner_(passport::CreateMaidAndSigner()),
      client_routing_(kMaidAndSigner_.first),
      functors_(),
      client_nfs_(),
      kPublicPmids_(public_pmids),
      public_pmid_helper_(),
      call_once_(false) {
  passport::PublicPmid::Name pmid_hint(Identity(NodeId(NodeId::kRandomId)));  //TODO This should be removed from client NFS
  client_nfs_.reset(new nfs_client::MaidNodeNfs(asio_service_, client_routing_, pmid_hint));
  {
    vault_manager::ClientInterface client_interface(kMaidAndSigner_.first);
    auto future(RoutingJoin(client_interface.GetBootstrapContacts().get()));
    auto status(future.wait_for(std::chrono::minutes(1)));
    if (status == std::future_status::timeout || !future.get()) {
      LOG(kError) << "can't join routing network";
      BOOST_THROW_EXCEPTION(MakeError(RoutingErrors::not_connected));
    }
    LOG(kInfo) << "Client node joined routing network";
  }
  passport::PublicMaid public_maid(kMaidAndSigner_.first);
  passport::PublicAnmaid public_anmaid(kMaidAndSigner_.second);
  auto account_creation_future(client_nfs_->CreateAccount(nfs_vault::AccountCreation(public_maid,
                                                                                     public_anmaid)));
  account_creation_future.get();
 // waiting for syncs resolved
//    Sleep(std::chrono::seconds(2));
  TLOG(kDefaultColour) << "Account created for maid " << DebugId(public_maid.name()) << '\n';
}

PublicPmidStorer::~PublicPmidStorer() {}

std::future<bool> PublicPmidStorer::RoutingJoin(
    const routing::BootstrapContacts& bootstrap_contacts) {
  std::once_flag join_promise_set_flag;
  std::shared_ptr<std::promise<bool>> join_promise(std::make_shared<std::promise<bool>>());
  functors_.network_status = [&join_promise_set_flag, join_promise, this](int result) {
    LOG(kVerbose) << "Network health: " << result;
    if ((result == 100) && (!call_once_)) {
          call_once_ = true;
          join_promise->set_value(true);
    }
  };
  functors_.typed_message_and_caching.group_to_group.message_received =
      [&](const routing::GroupToGroupMessage &msg) { client_nfs_->HandleMessage(msg); }; // NOLINT
  functors_.typed_message_and_caching.group_to_single.message_received =
      [&](const routing::GroupToSingleMessage &msg) { client_nfs_->HandleMessage(msg); }; // NOLINT
  functors_.typed_message_and_caching.single_to_group.message_received =
      [&](const routing::SingleToGroupMessage &msg) { client_nfs_->HandleMessage(msg); }; // NOLINT
  functors_.typed_message_and_caching.single_to_single.message_received =
      [&](const routing::SingleToSingleMessage &msg) { client_nfs_->HandleMessage(msg); }; // NOLINT
  functors_.request_public_key =
      [&](const NodeId & node_id, const routing::GivePublicKeyFunctor & give_key) {
        nfs::detail::DoGetPublicKey(*client_nfs_, node_id, give_key,
                                    kPublicPmids_, public_pmid_helper_);
      };
  client_routing_.Join(functors_, bootstrap_contacts);
  return std::move(join_promise->get_future());
}

void PublicPmidStorer::Store() {
  size_t failures(0);
  for (auto& keychain : key_chain_list_) {
    try {
      auto store_future = StoreKey(passport::PublicPmid(keychain.pmid));
      store_future.get();
//      Sleep(std::chrono::seconds(2));
      auto pmid_future(client_nfs_->Get(passport::PublicPmid::Name(keychain.pmid.name())));
      if (EqualKeys<passport::PublicPmid>(passport::PublicPmid(keychain.pmid), pmid_future.get()))
        TLOG(kDefaultColour) << "Pmid " << DebugId(keychain.pmid.name())
                             << " PublicPmidKey stored and verified\n";
    } catch (const std::exception& e) {
      TLOG(kRed) << "Failed storing key chain of PMID " << DebugId(keychain.pmid.name())
                 << ": " << boost::diagnostic_information(e) << '\n';
      ++failures;
    }
  }
  if (failures) {
    TLOG(kRed) << "Could not store " << std::to_string(failures) << " out of "
               << std::to_string(key_chain_list_.size()) << '\n';
    BOOST_THROW_EXCEPTION(MakeError(VaultErrors::failed_to_handle_request));
  }

//  Sleep(std::chrono::seconds(5));
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
