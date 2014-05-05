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
#include "boost/process/child.hpp"

#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

struct VaultInfo {
  VaultInfo();
  VaultInfo(VaultInfo&& other);
  VaultInfo& operator=(VaultInfo other);

  std::unique_ptr<passport::Pmid> pmid;
  boost::filesystem::path chunkstore_path;
  passport::PublicMaid::Name owner_name;
  bool joined_network;
  std::string label;
  boost::process::child process;
  std::vector<std::string> process_args;
  TcpConnectionPtr tcp_connection;
#ifdef TESTING
  int identity_index;
#endif

 private:
  VaultInfo(const VaultInfo&) = delete;
};

void swap(VaultInfo& lhs, VaultInfo& rhs);

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_INFO_H_
