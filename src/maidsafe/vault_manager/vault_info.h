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

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/process.h"
#include "maidsafe/passport/types.h"

namespace maidsafe {

namespace vault_manager {

struct VaultInfo {
  VaultInfo()
    : process_info(0),
      pmid(),
      chunkstore_path(),
      owner_name(),
      vault_port(0),
      client_port(0),
      joined_network(false),
#ifdef TESTING
      identity_index(-1),
#endif
      label() {}

  process::ProcessInfo process_info;
  std::unique_ptr<passport::Pmid> pmid;
  boost::filesystem::path chunkstore_path;
  std::unique_ptr<passport::PublicMaid::Name> owner_name;
  uint16_t vault_port, client_port;
  bool joined_network;
#ifdef TESTING
  int identity_index;
#endif
  std::string label;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_VAULT_INFO_H_
