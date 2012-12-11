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

#ifndef MAIDSAFE_PRIVATE_UTILS_UTILITIES_H_
#define MAIDSAFE_PRIVATE_UTILS_UTILITIES_H_

#include <chrono>
#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

#include "maidsafe/common/rsa.h"

namespace maidsafe {

namespace priv {

namespace utils {

enum ChunkStoreResult {
  kOperationTimeOut = -3,
  kPendingResult = -2,
  kRemoteChunkStoreFailure = -1,
  kSuccess = 0
};

void ChunkStoreOperationCallback(const bool& response,
                                 std::mutex* mutex,
                                 std::condition_variable* cond_var,
                                 int* result);

int WaitForResults(std::mutex& mutex,
                   std::condition_variable& cond_var,
                   std::vector<int>& results,
                   std::chrono::seconds interval = std::chrono::seconds(1));

}  // namespace utils

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_UTILS_UTILITIES_H_
