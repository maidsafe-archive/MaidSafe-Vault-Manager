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

#ifndef MAIDSAFE_VAULT_MANAGER_MESSAGES_CHALLENGE_RESPONSE_H_
#define MAIDSAFE_VAULT_MANAGER_MESSAGES_CHALLENGE_RESPONSE_H_

#include <memory>

#include "maidsafe/common/config.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

// Client to VaultManager
struct ChallengeResponse {
  static const MessageTag tag = MessageTag::kChallengeResponse;

  ChallengeResponse() = default;
  ChallengeResponse(const ChallengeResponse&) = delete;
  ChallengeResponse(ChallengeResponse&& other) MAIDSAFE_NOEXCEPT
      : public_maid(std::move(other.public_maid)),
        signature(std::move(other.signature)) {}
  ChallengeResponse(passport::PublicMaid public_maid_in, asymm::Signature signature_in)
      : public_maid(maidsafe::make_unique<passport::PublicMaid>(std::move(public_maid_in))),
        signature(std::move(signature_in)) {}
  ~ChallengeResponse() = default;
  ChallengeResponse& operator=(const ChallengeResponse&) = delete;
  ChallengeResponse& operator=(ChallengeResponse&& other) MAIDSAFE_NOEXCEPT {
    public_maid = std::move(other.public_maid);
    signature = std::move(other.signature);
    return *this;
  };

  template <typename Archive>
  void load(Archive& archive) {
    passport::PublicMaid::Name public_maid_name;
    passport::PublicMaid::serialised_type serialised_public_maid;
    archive(public_maid_name, serialised_public_maid, signature);
    public_maid = maidsafe::make_unique<passport::PublicMaid>(std::move(public_maid_name),
                                                              std::move(serialised_public_maid));
  }

  template <typename Archive>
  void save(Archive& archive) const {
    archive(public_maid->name(), public_maid->Serialise(), signature);
  }

  std::unique_ptr<passport::PublicMaid> public_maid;
  asymm::Signature signature;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_MESSAGES_CHALLENGE_RESPONSE_H_
