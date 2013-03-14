/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

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
