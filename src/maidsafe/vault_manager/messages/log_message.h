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

#ifndef MAIDSAFE_VAULT_MANAGER_MESSAGES_LOG_MESSAGE_H_
#define MAIDSAFE_VAULT_MANAGER_MESSAGES_LOG_MESSAGE_H_

#include <string>

#include "maidsafe/common/config.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

struct LogMessage {
  static const MessageTag tag = MessageTag::kLogMessage;

  LogMessage() = default;
  LogMessage(const LogMessage&) = delete;
  LogMessage(LogMessage&& other) MAIDSAFE_NOEXCEPT : data(std::move(other.data)) {}
  explicit LogMessage(std::string data_in) : data(std::move(data_in)) {}
  ~LogMessage() = default;
  LogMessage& operator=(const LogMessage&) = delete;
  LogMessage& operator=(LogMessage&& other) MAIDSAFE_NOEXCEPT {
    data = std::move(other.data);
    return *this;
  };

  template <typename Archive>
  void serialize(Archive& archive) {
    archive(data);
  }

  std::string data;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_MESSAGES_LOG_MESSAGE_H_
