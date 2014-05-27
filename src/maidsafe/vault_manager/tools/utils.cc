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

ClientTester::ClientTester(const passport::detail::AnmaidToPmid& key_chain,
                           const std::vector<passport::PublicPmid>& public_pmids,
                           bool register_pmid_for_client)
    : asio_service_(2),
      key_chain_(key_chain),
      client_routing_(key_chain.maid),
      functors_(),
      client_nfs_(),
      kPublicPmids_(public_pmids),
      public_pmid_helper_(),
      call_once_(false) {
  passport::PublicPmid::Name pmid_name(Identity(key_chain.pmid.name().value));
  client_nfs_.reset(new nfs_client::MaidNodeNfs(asio_service_, client_routing_, pmid_name));
  {
    vault_manager::ClientInterface client_interface(key_chain.maid);
    auto future(RoutingJoin(client_interface.GetBootstrapContacts().get()));
    auto status(future.wait_for(std::chrono::minutes(1)));
    if (status == std::future_status::timeout || !future.get()) {
      LOG(kError) << "can't join routing network";
      BOOST_THROW_EXCEPTION(MakeError(RoutingErrors::not_connected));
    }
    LOG(kInfo) << "Client node joined routing network";
  }
  bool account_exists(false);
  passport::PublicMaid public_maid(key_chain.maid);
  {
    passport::PublicAnmaid public_anmaid(key_chain.anmaid);
    auto future(client_nfs_->CreateAccount(nfs_vault::AccountCreation(public_maid,
                                                                      public_anmaid)));
    auto status(future.wait_for(boost::chrono::seconds(10)));
    if (status == boost::future_status::timeout) {
      LOG(kError) << "can't create account";
      BOOST_THROW_EXCEPTION(MakeError(VaultErrors::failed_to_handle_request));
    }
    if (future.has_exception()) {
      LOG(kError) << "having error during create account";
      try {
        future.get();
      } catch (const maidsafe_error& error) {
        LOG(kError) << "caught a maidsafe_error : " << boost::diagnostic_information(error);
        if (error.code() == make_error_code(VaultErrors::account_already_exists))
          account_exists = true;
      } catch (...) {
        LOG(kError) << "caught an unknown exception";
      }
    }
  }
  if (account_exists) {
    TLOG(kDefaultColour) << "Account exists for maid " << DebugId(public_maid.name()) << '\n';
    register_pmid_for_client = false;
  } else {
    // waiting for syncs resolved
    Sleep(std::chrono::seconds(2));
    TLOG(kDefaultColour) << "Account created for maid " << DebugId(public_maid.name()) << '\n';
    // before register pmid, need to store pmid to network first
    client_nfs_->Put(passport::PublicPmid(key_chain.pmid));
    Sleep(std::chrono::seconds(2));
  }

  if (register_pmid_for_client) {
    {
      client_nfs_->RegisterPmid(nfs_vault::PmidRegistration(key_chain.maid, key_chain.pmid, false));
      Sleep(std::chrono::seconds(3));
      auto future(client_nfs_->GetPmidHealth(pmid_name));
      auto status(future.wait_for(boost::chrono::seconds(10)));
      if (status == boost::future_status::timeout) {
        LOG(kError) << "can't fetch pmid health";
        BOOST_THROW_EXCEPTION(MakeError(VaultErrors::failed_to_handle_request));
      }
      TLOG(kDefaultColour) << "The fetched PmidHealth for pmid_name " << DebugId(pmid_name)
                           << " is " << future.get() << '\n';
    }
    // waiting for the GetPmidHealth updating corresponding accounts
    Sleep(std::chrono::seconds(3));
    LOG(kInfo) << "Pmid Registered created for the client node to store chunks";
  }
}

ClientTester::~ClientTester() {}

std::future<bool> ClientTester::RoutingJoin(const routing::BootstrapContacts& bootstrap_contacts) {
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

KeyStorer::KeyStorer(const passport::detail::AnmaidToPmid& key_chain,
                     const std::vector<passport::PublicPmid>& public_pmids,
                     const KeyChainVector& key_chain_list)
    : ClientTester(key_chain, public_pmids, false),
      key_chain_list_(key_chain_list) {}

void KeyStorer::Store() {
  size_t failures(0);
  for (auto& keychain : key_chain_list_) {
    try {
      StoreKey(passport::PublicPmid(keychain.pmid));
      Sleep(std::chrono::seconds(2));
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

  Sleep(std::chrono::seconds(5));
}

KeyVerifier::KeyVerifier(const passport::detail::AnmaidToPmid& key_chain,
                         const std::vector<passport::PublicPmid>& public_pmids)
    : ClientTester(key_chain, public_pmids, false) {}

void KeyVerifier::Verify() {
  try {
    auto anmaid_future(client_nfs_->Get(passport::PublicAnmaid::Name(key_chain_.anmaid.name())));
    auto maid_future(client_nfs_->Get(passport::PublicMaid::Name(key_chain_.maid.name())));
    auto pmid_future(client_nfs_->Get(passport::PublicPmid::Name(key_chain_.pmid.name())));

    size_t verified_keys(0);
    if (EqualKeys<passport::PublicAnmaid>(passport::PublicAnmaid(key_chain_.anmaid),
                                          anmaid_future.get()))
      ++verified_keys;
    if (EqualKeys<passport::PublicMaid>(passport::PublicMaid(key_chain_.maid), maid_future.get()))
      ++verified_keys;
    if (EqualKeys<passport::PublicPmid>(passport::PublicPmid(key_chain_.pmid), pmid_future.get()))
      ++verified_keys;
    TLOG(kGreen) << "VerifyKeys - Verified all " << verified_keys << " keys.\n";
  }
  catch (const std::exception& ex) {
    TLOG(kRed) << "Failed to verify keys " << boost::diagnostic_information(ex) << '\n';
  }
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
