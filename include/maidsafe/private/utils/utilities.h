/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of maidsafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the license file LICENSE.TXT found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of maidsafe.net.                                          *
 ***********************************************************************************************//**
 * @file  utilities.cc
 * @brief Generic utility functions.
 * @date  2012-07-26
 */

#ifndef MAIDSAFE_PRIVATE_UTILS_UTILITIES_H_
#define MAIDSAFE_PRIVATE_UTILS_UTILITIES_H_

#include <string>

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/rsa.h"

namespace asymm = maidsafe::rsa;

namespace maidsafe {

namespace priv {

namespace utilities {

enum ChunkStoreResult {
  kOperationTimeOut = -3,
  kPendingResult = -2,
  kRemoteChunkStoreFailure = -1,
  kSuccess = 0
};

std::string SerialisedSignedData(const asymm::Keys &keys);

int CreateMaidsafeIdentity(asymm::Keys& keys);

void ChunkStoreOperationCallback(const bool &response,
                                 boost::mutex *mutex,
                                 boost::condition_variable *cond_var,
                                 int *result);

int WaitForResults(boost::mutex& mutex,
                   boost::condition_variable& cond_var,
                   std::vector<int>& results);

}  // namespace utilities

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_UTILS_UTILITIES_H_
