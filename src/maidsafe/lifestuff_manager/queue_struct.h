/*  Copyright 2012 MaidSafe.net limited

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

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_QUEUE_STRUCT_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_QUEUE_STRUCT_H_

#include "boost/interprocess/sync/interprocess_mutex.hpp"
#include "boost/interprocess/sync/interprocess_condition.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"

namespace maidsafe {

namespace lifestuff_manager {

namespace detail {

// IpcBidirectionalQueue and SafeAddress contain only POD types. Any other type has to be given an
// allocator to use the reserved shared memory as a construction ground.
struct IpcBidirectionalQueue {
  enum {
    kMessageSize = 100000
  };

  IpcBidirectionalQueue()
      : cwpr_mutex(),
        pwcr_mutex(),
        parent_read(),
        parent_write(),
        child_read(),
        child_write(),
        message_from_parent(false),
        message_from_child(false) {}
  boost::interprocess::interprocess_mutex cwpr_mutex, pwcr_mutex;
  boost::interprocess::interprocess_condition parent_read, parent_write, child_read, child_write;
  char parent_message[kMessageSize], child_message[kMessageSize];
  bool message_from_parent, message_from_child;
};

struct SafeAddress {
  SafeAddress() : mutex() {}
  boost::interprocess::interprocess_mutex mutex;
  char address[crypto::SHA512::DIGESTSIZE], signature[asymm::Keys::kSignatureByteSize];
};

}  // namespace detail

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_QUEUE_STRUCT_H_
