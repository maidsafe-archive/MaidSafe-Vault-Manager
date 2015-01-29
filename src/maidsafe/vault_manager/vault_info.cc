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
      vault_dir(),
      max_disk_usage(0),
      owner_name(),
      label(),
#ifdef USE_VLOGGING
      vlog_session_id(),
      send_hostname_to_visualiser_server(false),
#endif
      tcp_connection() {
}

VaultInfo::VaultInfo(const VaultInfo& other)
    : pmid_and_signer(other.pmid_and_signer),
      vault_dir(other.vault_dir),
      max_disk_usage(other.max_disk_usage),
      owner_name(other.owner_name),
      label(other.label),
#ifdef USE_VLOGGING
      vlog_session_id(other.vlog_session_id),
      send_hostname_to_visualiser_server(other.send_hostname_to_visualiser_server),
#endif
      tcp_connection(other.tcp_connection) {
}

VaultInfo::VaultInfo(VaultInfo&& other)
    : pmid_and_signer(std::move(other.pmid_and_signer)),
      vault_dir(std::move(other.vault_dir)),
      max_disk_usage(std::move(other.max_disk_usage)),
      owner_name(std::move(other.owner_name)),
      label(std::move(other.label)),
#ifdef USE_VLOGGING
      vlog_session_id(std::move(other.vlog_session_id)),
      send_hostname_to_visualiser_server(std::move(other.send_hostname_to_visualiser_server)),
#endif
      tcp_connection(std::move(other.tcp_connection)) {
}

VaultInfo& VaultInfo::operator=(VaultInfo other) {
  swap(*this, other);
  return *this;
}

void swap(VaultInfo& lhs, VaultInfo& rhs) {
  using std::swap;
  swap(lhs.pmid_and_signer, rhs.pmid_and_signer);
  swap(lhs.vault_dir, rhs.vault_dir);
  swap(lhs.max_disk_usage, rhs.max_disk_usage);
  swap(lhs.owner_name, rhs.owner_name);
  swap(lhs.label, rhs.label);
#ifdef USE_VLOGGING
  swap(lhs.vlog_session_id, rhs.vlog_session_id);
  swap(lhs.send_hostname_to_visualiser_server, rhs.send_hostname_to_visualiser_server);
#endif
  swap(lhs.tcp_connection, rhs.tcp_connection);
}

}  // namespace vault_manager

}  // namespace maidsafe
