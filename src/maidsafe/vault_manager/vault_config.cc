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

#include "maidsafe/vault_manager/vault_config.h"

#include <utility>

namespace maidsafe {

namespace vault_manager {

VaultConfig::VaultConfig(const passport::Pmid& pmid_in,
                         const boost::filesystem::path& chunkstore_path_in,
                         const DiskUsage& max_disk_usage_in,
                         routing::BootstrapContacts bootstrap_contacts_in)
    : pmid(pmid_in),
      chunkstore_path(chunkstore_path_in),
      max_disk_usage(max_disk_usage_in),
#ifdef TESTING
      test_config(),
#endif
      bootstrap_contacts(bootstrap_contacts_in) {}

VaultConfig::VaultConfig(const VaultConfig& other)
    : pmid(other.pmid),
      chunkstore_path(other.chunkstore_path),
      max_disk_usage(other.max_disk_usage),
#ifdef TESTING
      test_config(other.test_config),
#endif
      bootstrap_contacts(other.bootstrap_contacts) {}

VaultConfig::VaultConfig(VaultConfig&& other)
    : pmid(std::move(other.pmid)),
      chunkstore_path(std::move(other.chunkstore_path)),
      max_disk_usage(std::move(other.max_disk_usage)),
#ifdef TESTING
      test_config(std::move(other.test_config)),
#endif
      bootstrap_contacts(std::move(other.bootstrap_contacts)) {}

VaultConfig& VaultConfig::operator=(VaultConfig other) {
  swap(*this, other);
  return *this;
}

void swap(VaultConfig& lhs, VaultConfig& rhs) {
  using std::swap;
  swap(lhs.pmid, rhs.pmid);
  swap(lhs.chunkstore_path, rhs.chunkstore_path);
  swap(lhs.max_disk_usage, rhs.max_disk_usage);
#ifdef TESTING
  swap(lhs.test_config, rhs.test_config);
#endif
  swap(lhs.bootstrap_contacts, rhs.bootstrap_contacts);
}

}  // namespace vault_manager

}  // namespace maidsafe
