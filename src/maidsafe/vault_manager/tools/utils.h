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

#ifndef MAIDSAFE_VAULT_MANAGER_TOOLS_UTILS_H_
#define MAIDSAFE_VAULT_MANAGER_TOOLS_UTILS_H_

#include <deque>
#include <memory>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/passport/passport.h"

#include "maidsafe/routing/api_config.h"
#include "maidsafe/routing/node_info.h"
#include "maidsafe/routing/routing_api.h"

#include "maidsafe/nfs/client/data_getter.h"
#include "maidsafe/nfs/client/maid_node_nfs.h"

#include "maidsafe/vault_manager/client_interface.h"
#include "maidsafe/vault_manager/vault_manager.h"

namespace maidsafe {

namespace vault_manager {

namespace tools {


class PublicPmidStorer {
 public:
  PublicPmidStorer(const std::vector<passport::PublicPmid>& public_pmids);
  void Store();
 private:
  template <typename SigningData>
  bool EqualKeys(const SigningData& lhs, const SigningData& rhs) {
    return lhs.name() == rhs.name() && asymm::MatchingKeys(lhs.public_key(), rhs.public_key());
  }

  ~PublicPmidStorer();
  std::future<bool> RoutingJoin(const routing::BootstrapContacts& bootstrap_contacts);

  AsioService asio_service_;
  const passport::MaidAndSigner kMaidAndSigner_;
  routing::Routing client_routing_;
  routing::Functors functors_;
  std::unique_ptr<nfs_client::MaidNodeNfs> client_nfs_;
  std::vector<passport::PublicPmid> kPublicPmids_;
  nfs::detail::PublicPmidHelper public_pmid_helper_;
  std::atomic<bool> call_once_;
};

class KeyStorer : public ClientTester {
 public:
  KeyStorer(const passport::detail::AnmaidToPmid& key_chain,
            const std::vector<passport::PublicPmid>& public_pmids,
            const KeyChainVector& key_chain_list);
  void Store();

 private:
  template <typename Data>
  boost::future<void> StoreKey(const Data& key) {
    return client_nfs_->Put(key);
  }
  KeyChainVector key_chain_list_;
};

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_TOOLS_UTILS_H_
