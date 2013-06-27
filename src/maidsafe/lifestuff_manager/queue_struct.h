/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
  enum { kMessageSize = 100000 };

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
