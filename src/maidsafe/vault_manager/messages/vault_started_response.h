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

#ifndef MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_STARTED_RESPONSE_H_
#define MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_STARTED_RESPONSE_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/serialisation/types/boost_filesystem.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

// VaultManager to Vault
struct VaultStartedResponse {
  static const MessageTag tag = MessageTag::kVaultStartedResponse;

  VaultStartedResponse() = default;

  VaultStartedResponse(const VaultStartedResponse&) = delete;

  VaultStartedResponse(VaultStartedResponse&& other) MAIDSAFE_NOEXCEPT
      : symm_key(std::move(other.symm_key)),
        symm_iv(std::move(other.symm_iv)),
        pmid(std::move(other.pmid)),
        vault_dir(std::move(other.vault_dir)),
#ifdef USE_VLOGGING
        vlog_session_id(std::move(other.vlog_session_id)),
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
        send_hostname_to_visualiser_server(std::move(other.send_hostname_to_visualiser_server)),
#endif
#ifdef TESTING
        public_pmids(std::move(other.public_pmids)),
#endif
        max_disk_usage(std::move(other.max_disk_usage)) {
  }

  VaultStartedResponse(const VaultInfo& vault_info, crypto::AES256Key symm_key_in,
                       crypto::AES256InitialisationVector symm_iv_in)
      : symm_key(std::move(symm_key_in)),
        symm_iv(std::move(symm_iv_in)),
        pmid(maidsafe::make_unique<passport::Pmid>(vault_info.pmid_and_signer->first)),
        vault_dir(vault_info.vault_dir),
#ifdef USE_VLOGGING
        vlog_session_id(vault_info.vlog_session_id),
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
        send_hostname_to_visualiser_server(vault_info.send_hostname_to_visualiser_server),
#endif
#ifdef TESTING
        public_pmids(GetPublicPmids()),
#endif
        max_disk_usage(vault_info.max_disk_usage) {
  }

  ~VaultStartedResponse() = default;

  VaultStartedResponse& operator=(const VaultStartedResponse&) = delete;

  VaultStartedResponse& operator=(VaultStartedResponse&& other) MAIDSAFE_NOEXCEPT {
    symm_key = std::move(other.symm_key);
    symm_iv = std::move(other.symm_iv);
    pmid = std::move(other.pmid);
    vault_dir = std::move(other.vault_dir);
#ifdef USE_VLOGGING
    vlog_session_id = std::move(other.vlog_session_id);
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
    send_hostname_to_visualiser_server = std::move(other.send_hostname_to_visualiser_server);
#endif
#ifdef TESTING
    public_pmids = std::move(other.public_pmids);
#endif
    max_disk_usage = std::move(other.max_disk_usage);
    return *this;
  };

  template <typename Archive>
  void load(Archive& archive) {
    crypto::CipherText encrypted_pmid;
    archive(symm_key, symm_iv, encrypted_pmid, vault_dir);
    pmid = maidsafe::make_unique<passport::Pmid>(
        passport::DecryptPmid(encrypted_pmid, symm_key, symm_iv));
#ifdef USE_VLOGGING
    archive(vlog_session_id);
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
    archive(send_hostname_to_visualiser_server);
#endif
#ifdef TESTING
    std::size_t public_pmid_count(0);
    archive(public_pmid_count);
    for (std::size_t i(0); i < public_pmid_count; ++i) {
      passport::PublicPmid::Name public_pmid_name;
      passport::PublicPmid::serialised_type serialised_public_pmid;
      archive(public_pmid_name, serialised_public_pmid);
      public_pmids.emplace_back(std::move(public_pmid_name), std::move(serialised_public_pmid));
    }
#endif
    archive(max_disk_usage);
  }

  template <typename Archive>
  void save(Archive& archive) const {
    archive(symm_key, symm_iv, passport::EncryptPmid(*pmid, symm_key, symm_iv), vault_dir);
#ifdef USE_VLOGGING
    archive(vlog_session_id);
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
    archive(send_hostname_to_visualiser_server);
#endif
#ifdef TESTING
    archive(public_pmids.size());
    for (const auto& public_pmid : public_pmids)
      archive(public_pmid.name(), public_pmid.Serialise());
#endif
    archive(max_disk_usage);
  }

  crypto::AES256Key symm_key;
  crypto::AES256InitialisationVector symm_iv;
  std::unique_ptr<passport::Pmid> pmid;
  boost::filesystem::path vault_dir;
#ifdef USE_VLOGGING
  std::string vlog_session_id;
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
  bool send_hostname_to_visualiser_server;
#endif
#ifdef TESTING
  std::vector<passport::PublicPmid> public_pmids;
#endif
  DiskUsage max_disk_usage;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_MESSAGES_VAULT_STARTED_RESPONSE_H_
