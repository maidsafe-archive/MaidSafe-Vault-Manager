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

#ifndef MAIDSAFE_VAULT_MANAGER_CONFIG_FILE_H_
#define MAIDSAFE_VAULT_MANAGER_CONFIG_FILE_H_

#include <memory>
#include <vector>

#include "maidsafe/common/config.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/serialisation/types/boost_filesystem.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

// Vault to VaultManager
struct ConfigFile {
  ConfigFile() = default;

  ConfigFile(const ConfigFile&) = delete;

  ConfigFile(ConfigFile&& other) MAIDSAFE_NOEXCEPT : symm_key(std::move(other.symm_key)),
                                                     symm_iv(std::move(other.symm_iv)),
                                                     vaults(std::move(other.vaults)) {}

  ConfigFile(crypto::AES256Key symm_key_in, crypto::AES256InitialisationVector symm_iv_in,
             std::vector<VaultInfo> vaults_in)
      : symm_key(std::move(symm_key_in)),
        symm_iv(std::move(symm_iv_in)),
        vaults(std::move(vaults_in)) {}

  ~ConfigFile() = default;

  ConfigFile& operator=(const ConfigFile&) = delete;

  ConfigFile& operator=(ConfigFile&& other) MAIDSAFE_NOEXCEPT {
    symm_key = std::move(other.symm_key);
    symm_iv = std::move(other.symm_iv);
    vaults = std::move(other.vaults);
    return *this;
  };

  template <typename Archive>
  void load(Archive& archive) {
    std::size_t vault_count(0);
    archive(symm_key, symm_iv, vault_count);
    for (std::size_t i(0); i < vault_count; ++i) {
      VaultInfo vault;
      crypto::CipherText encrypted_pmid, encrypted_anpmid;
      bool has_owner_name(false);
      archive(encrypted_pmid, encrypted_anpmid, vault.vault_dir, vault.label, vault.max_disk_usage,
              has_owner_name);
      vault.pmid_and_signer = std::make_shared<passport::PmidAndSigner>(
          std::make_pair(passport::DecryptPmid(encrypted_pmid, symm_key, symm_iv),
                         passport::DecryptAnpmid(encrypted_anpmid, symm_key, symm_iv)));
      if (has_owner_name)
        archive(vault.owner_name);
    }
  }

  template <typename Archive>
  void save(Archive& archive) const {
    archive(symm_key, symm_iv, vaults.size());
    for (const auto& vault : vaults) {
      archive(passport::EncryptPmid(vault.pmid_and_signer->first, symm_key, symm_iv),
              passport::EncryptAnpmid(vault.pmid_and_signer->second, symm_key, symm_iv),
              vault.vault_dir, vault.label, vault.max_disk_usage,
              vault.owner_name->IsInitialised());
      if (vault.owner_name->IsInitialised())
        archive(vault.owner_name);
    }
  }

  crypto::AES256Key symm_key;
  crypto::AES256InitialisationVector symm_iv;
  std::vector<VaultInfo> vaults;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_CONFIG_FILE_H_
