/*  Copyright 2015 MaidSafe.net limited

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

#ifndef MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_STARTED_H_
#define MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_STARTED_H_

#include "maidsafe/common/config.h"
#include "maidsafe/common/process.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

// Vault to VaultManager
struct VaultStarted {
  static const MessageTag tag = MessageTag::kVaultStarted;

  VaultStarted() = default;
  VaultStarted(const VaultStarted&) = delete;
  VaultStarted(VaultStarted&& other) MAIDSAFE_NOEXCEPT : process_id(std::move(other.process_id)) {}
  explicit VaultStarted(process::ProcessId process_id_in) : process_id(process_id_in) {}
  ~VaultStarted() = default;
  VaultStarted& operator=(const VaultStarted&) = delete;
  VaultStarted& operator=(VaultStarted&& other) MAIDSAFE_NOEXCEPT {
    process_id = std::move(other.process_id);
    return *this;
  };

  template <typename Archive>
  void serialize(Archive& archive) {
    archive(process_id);
  }

  process::ProcessId process_id;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_STARTED_H_
