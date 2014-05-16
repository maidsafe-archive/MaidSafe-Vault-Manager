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

#ifndef MAIDSAFE_VAULT_MANAGER_VAULT_INFO_H_
#define MAIDSAFE_VAULT_MANAGER_VAULT_INFO_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/types.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

struct VaultInfo {
  VaultInfo();
  VaultInfo(const VaultInfo&);
  VaultInfo(VaultInfo&& other);
  VaultInfo& operator=(VaultInfo other);

  std::shared_ptr<passport::PmidAndSigner> pmid_and_signer;
  boost::filesystem::path vault_dir;
  DiskUsage max_disk_usage;
  passport::PublicMaid::Name owner_name;
  bool joined_network;
  NonEmptyString label;
#ifdef TESTING
  int identity_index;
#endif
  TcpConnectionPtr tcp_connection;
};

void swap(VaultInfo& lhs, VaultInfo& rhs);

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_INFO_H_
