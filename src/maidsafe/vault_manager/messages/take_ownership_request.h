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

#ifndef MAIDSAFE_VAULT_MANAGER_MESSAGES_TAKE_OWNERSHIP_REQUEST_H_
#define MAIDSAFE_VAULT_MANAGER_MESSAGES_TAKE_OWNERSHIP_REQUEST_H_

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/serialisation/types/boost_filesystem.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

// Client to VaultManager
struct TakeOwnershipRequest {
  static const MessageTag tag = MessageTag::kTakeOwnershipRequest;

  TakeOwnershipRequest() = default;

  TakeOwnershipRequest(const TakeOwnershipRequest&) = delete;

  TakeOwnershipRequest(TakeOwnershipRequest&& other) MAIDSAFE_NOEXCEPT
      : vault_label(std::move(other.vault_label)),
        vault_dir(std::move(other.vault_dir)),
        max_disk_usage(std::move(other.max_disk_usage)) {}

  TakeOwnershipRequest(NonEmptyString vault_label_in, boost::filesystem::path vault_dir_in,
                       DiskUsage max_disk_usage_in)
      : vault_label(std::move(vault_label_in)),
        vault_dir(std::move(vault_dir_in)),
        max_disk_usage(std::move(max_disk_usage_in)) {}

  ~TakeOwnershipRequest() = default;

  TakeOwnershipRequest& operator=(const TakeOwnershipRequest&) = delete;

  TakeOwnershipRequest& operator=(TakeOwnershipRequest&& other) MAIDSAFE_NOEXCEPT {
    vault_label = std::move(other.vault_label);
    vault_dir = std::move(other.vault_dir);
    max_disk_usage = std::move(other.max_disk_usage);
    return *this;
  };

  template <typename Archive>
  void serialize(Archive& archive) {
    archive(vault_label, vault_dir, max_disk_usage);
  }

  NonEmptyString vault_label;
  boost::filesystem::path vault_dir;
  DiskUsage max_disk_usage;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_MESSAGES_TAKE_OWNERSHIP_REQUEST_H_
