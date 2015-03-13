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

#ifndef MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_RUNNING_RESPONSE_H_
#define MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_RUNNING_RESPONSE_H_

#include <memory>

#include "boost/optional.hpp"
#include "cereal/types/boost_optional.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

// VaultManager to Client
struct VaultRunningResponse {
  static const MessageTag tag = MessageTag::kVaultRunningResponse;

  struct VaultKeys {
    VaultKeys() = default;

    VaultKeys(const VaultKeys&) = default;

    VaultKeys(VaultKeys&& other) MAIDSAFE_NOEXCEPT
        : symm_key_and_iv(std::move(other.symm_key_and_iv)),
          pmid_and_signer(std::move(other.pmid_and_signer)) {}

    explicit VaultKeys(passport::PmidAndSigner pmid_and_signer_in)
        : symm_key_and_iv(RandomBytes(crypto::AES256_KeySize + crypto::AES256_IVSize)),
          pmid_and_signer(
              std::make_shared<passport::PmidAndSigner>(std::move(pmid_and_signer_in))) {}

    ~VaultKeys() = default;

    VaultKeys& operator=(const VaultKeys&) = default;

    VaultKeys& operator=(VaultKeys&& other) MAIDSAFE_NOEXCEPT {
      symm_key_and_iv = std::move(other.symm_key_and_iv);
      pmid_and_signer = std::move(other.pmid_and_signer);
      return *this;
    };

    template <typename Archive>
    void load(Archive& archive) {
      crypto::CipherText encrypted_anpmid, encrypted_pmid;
      archive(symm_key_and_iv, encrypted_anpmid, encrypted_pmid);
      pmid_and_signer = std::make_shared<passport::PmidAndSigner>(
          std::make_pair(passport::DecryptPmid(encrypted_pmid, symm_key_and_iv),
                         passport::DecryptAnpmid(encrypted_anpmid, symm_key_and_iv)));
    }

    template <typename Archive>
    void save(Archive& archive) const {
      archive(symm_key_and_iv,
              passport::EncryptAnpmid(pmid_and_signer->second, symm_key_and_iv),
              passport::EncryptPmid(pmid_and_signer->first, symm_key_and_iv));
    }

    crypto::AES256KeyAndIV symm_key_and_iv;
    std::shared_ptr<passport::PmidAndSigner> pmid_and_signer;
  };



  VaultRunningResponse() = default;

  VaultRunningResponse(const VaultRunningResponse&) = delete;

  VaultRunningResponse(VaultRunningResponse&& other) MAIDSAFE_NOEXCEPT
      : vault_label(std::move(other.vault_label)),
        vault_keys(std::move(other.vault_keys)),
        error(std::move(other.error)) {
    ValidateOptions();
  }

  VaultRunningResponse(NonEmptyString vault_label_in, passport::PmidAndSigner pmid_and_signer)
      : vault_label(std::move(vault_label_in)), vault_keys(std::move(pmid_and_signer)), error() {}

  VaultRunningResponse(NonEmptyString vault_label_in, maidsafe_error error_in)
      : vault_label(std::move(vault_label_in)), vault_keys(), error(std::move(error_in)) {}

  ~VaultRunningResponse() = default;

  VaultRunningResponse& operator=(const VaultRunningResponse&) = delete;

  VaultRunningResponse& operator=(VaultRunningResponse&& other) MAIDSAFE_NOEXCEPT {
    vault_label = std::move(other.vault_label);
    vault_keys = std::move(other.vault_keys);
    error = std::move(other.error);
    ValidateOptions();
    return *this;
  };

  void ValidateOptions() const {
    if ((vault_keys && error) || (!vault_keys && !error)) {
      LOG(kError) << "Should contain exactly one of vault keys or error.";
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_argument));
    }
  }

  template <typename Archive>
  void load(Archive& archive) {
    archive(vault_label, vault_keys, error);
    ValidateOptions();
  }

  template <typename Archive>
  void save(Archive& archive) const {
    ValidateOptions();
    archive(vault_label, vault_keys, error);
  }

  NonEmptyString vault_label;
  boost::optional<VaultKeys> vault_keys;
  boost::optional<maidsafe_error> error;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_RUNNING_RESPONSE_H_
