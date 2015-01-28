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

#ifndef MAIDSAFE_VAULT_MANAGER_MESSAGES_START_VAULT_REQUEST_H_
#define MAIDSAFE_VAULT_MANAGER_MESSAGES_START_VAULT_REQUEST_H_

#include <string>

#include "boost/filesystem/path.hpp"
#include "boost/optional.hpp"
#include "cereal/types/boost_optional.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/types.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

// Client to VaultManager
struct StartVaultRequest {
  static const MessageTag tag = MessageTag::kStartVaultRequest;

  StartVaultRequest() = default;

  StartVaultRequest(const StartVaultRequest&) = delete;

  StartVaultRequest(StartVaultRequest&& other) MAIDSAFE_NOEXCEPT
      : vault_label(std::move(other.vault_label)),
        vault_dir(std::move(other.vault_dir)),
#ifdef USE_VLOGGING
        vlog_session_id(std::move(other.vlog_session_id)),
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
        send_hostname_to_visualiser_server(std::move(other.send_hostname_to_visualiser_server)),
#endif
#ifdef TESTING
        pmid_list_index(std::move(other.pmid_list_index)),
#endif
        max_disk_usage(std::move(other.max_disk_usage)) {
  }

  StartVaultRequest(NonEmptyString vault_label_in, boost::filesystem::path vault_dir_in,
                    DiskUsage max_disk_usage_in)
      : vault_label(std::move(vault_label_in)),
        vault_dir(std::move(vault_dir_in)),
#ifdef USE_VLOGGING
        vlog_session_id(),
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
        send_hostname_to_visualiser_server(false),
#endif
#ifdef TESTING
        pmid_list_index(),
#endif
        max_disk_usage(std::move(max_disk_usage_in)) {
  }

  ~StartVaultRequest() = default;

  StartVaultRequest& operator=(const StartVaultRequest&) = delete;

  StartVaultRequest& operator=(StartVaultRequest&& other) MAIDSAFE_NOEXCEPT {
    vault_label = std::move(other.vault_label);
    vault_dir = std::move(other.vault_dir);
#ifdef USE_VLOGGING
    vlog_session_id = std::move(other.vlog_session_id);
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
    send_hostname_to_visualiser_server = std::move(other.send_hostname_to_visualiser_server);
#endif
#ifdef TESTING
    pmid_list_index = std::move(other.pmid_list_index);
#endif
    max_disk_usage = std::move(other.max_disk_usage);
    return *this;
  };

  template <typename Archive>
  void serialize(Archive& archive) {
    archive(vault_label, vault_dir, max_disk_usage);
#ifdef USE_VLOGGING
    archive(vlog_session_id);
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
    archive(send_hostname_to_visualiser_server);
#endif
#ifdef TESTING
    archive(pmid_list_index);
#endif
  }

  NonEmptyString vault_label;
  boost::filesystem::path vault_dir;
#ifdef USE_VLOGGING
  std::string vlog_session_id;
#endif
#if defined(USE_VLOGGING) && defined(TESTING)
  bool send_hostname_to_visualiser_server;
#endif
#ifdef TESTING
  boost::optional<int> pmid_list_index;
#endif
  DiskUsage max_disk_usage;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_MESSAGES_START_VAULT_REQUEST_H_
