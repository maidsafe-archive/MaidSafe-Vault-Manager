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

#include "maidsafe/vault_manager/vault_info.h"

#include <utility>

namespace maidsafe {

namespace vault_manager {

VaultInfo::VaultInfo()
    : pmid_and_signer(),
      chunkstore_path(),
      max_disk_usage(0),
      owner_name(),
      joined_network(false),
      label(),
#ifdef TESTING
      identity_index(-1),
#endif
      tcp_connection() {}

VaultInfo::VaultInfo(const VaultInfo& other)
    : pmid_and_signer(other.pmid_and_signer),
      chunkstore_path(other.chunkstore_path),
      max_disk_usage(other.max_disk_usage),
      owner_name(other.owner_name),
      joined_network(other.joined_network),
      label(other.label),
#ifdef TESTING
      identity_index(other.identity_index),
#endif
      tcp_connection(other.tcp_connection) {}

VaultInfo::VaultInfo(VaultInfo&& other)
    : pmid_and_signer(std::move(other.pmid_and_signer)),
      chunkstore_path(std::move(other.chunkstore_path)),
      max_disk_usage(std::move(other.max_disk_usage)),
      owner_name(std::move(other.owner_name)),
      joined_network(std::move(other.joined_network)),
      label(std::move(other.label)),
#ifdef TESTING
      identity_index(std::move(other.identity_index)),
#endif
      tcp_connection(std::move(other.tcp_connection)) {}

VaultInfo& VaultInfo::operator=(VaultInfo other) {
  swap(*this, other);
  return *this;
}

void swap(VaultInfo& lhs, VaultInfo& rhs) {
  using std::swap;
  swap(lhs.pmid_and_signer, rhs.pmid_and_signer);
  swap(lhs.chunkstore_path, rhs.chunkstore_path);
  swap(lhs.max_disk_usage, rhs.max_disk_usage);
  swap(lhs.owner_name, rhs.owner_name);
  swap(lhs.joined_network, rhs.joined_network);
  swap(lhs.label, rhs.label);
#ifdef TESTING
  swap(lhs.identity_index, rhs.identity_index);
#endif
  swap(lhs.tcp_connection, rhs.tcp_connection);
}

}  // namespace vault_manager

}  // namespace maidsafe
