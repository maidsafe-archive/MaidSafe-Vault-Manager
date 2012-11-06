/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file licence.txt found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_PRIVATE_DATA_MANAGER_STORE_POLICIES_H_
#define MAIDSAFE_PRIVATE_DATA_MANAGER_STORE_POLICIES_H_

#include "maidsafe/common/types.h"

class StoreToNetwork {
 protected:  // not exposing rich interface (public inheritance)
template <typename T>
  static bool Store(T) {
  // implementation
  }
};

class StoreToDisk {
 protected:
   template <typename T>
  static bool Store(const T data,
                    const NonEmptyString& content,
                    const asymm::PublicKey& public_key,
                    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {

};

#endif  // MAIDSAFE_PRIVATE_DATA_MANAGER_STORE_POLICIES_H_

