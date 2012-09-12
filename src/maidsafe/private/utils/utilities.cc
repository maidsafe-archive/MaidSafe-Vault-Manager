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

#include "maidsafe/private/utils/utilities.h"

#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_actions/chunk_pb.h"

namespace bptime = boost::posix_time;
namespace pca = maidsafe::priv::chunk_actions;

namespace maidsafe {

namespace priv {

namespace utilities {

std::string SerialisedSignedData(const asymm::Keys &keys) {
  std::string public_key;
  asymm::EncodePublicKey(keys.public_key, &public_key);
  pca::SignedData signed_data;
  signed_data.set_data(public_key);
  signed_data.set_signature(keys.validation_token);
  return signed_data.SerializeAsString();
}

int CreateMaidsafeIdentity(asymm::Keys& keys) {
  asymm::GenerateKeyPair(&keys);

  std::string encoded_public_key;
  asymm::EncodePublicKey(keys.public_key, &encoded_public_key);
  if (encoded_public_key.empty())
    return -111;

  asymm::Sign(encoded_public_key, keys.private_key, &keys.validation_token);
  if (keys.validation_token.empty())
    return -112;

  keys.identity = crypto::Hash<maidsafe::crypto::SHA512>(encoded_public_key +
                                                         keys.validation_token);

  return 0;
}

void ChunkStoreOperationCallback(const bool &response,
                                 std::mutex *mutex,
                                 std::condition_variable *cond_var,
                                 int *result) {
  if (!mutex || !cond_var || !result)
    return;
  std::unique_lock<std::mutex> lock(*mutex);
  if (response)
    *result = kSuccess;
  else
    *result = kRemoteChunkStoreFailure;
  cond_var->notify_all();
}

int WaitForResults(std::mutex& mutex,
                   std::condition_variable& cond_var,
                   std::vector<int>& results,
                   std::chrono::seconds interval) {
  assert(results.size() < 129U);  // Arbitrary decision
  int size(static_cast<int>(results.size()));
  try {
    std::unique_lock<std::mutex> lock(mutex);
    if (!cond_var.wait_for(lock,
                           interval * size,
                           [&]()->bool {
                             for (int i(0); i < size; ++i) {
                               if (results.at(i) == kPendingResult) {
                                 LOG(kInfo) << "Element " << i << " still pending.";
                                 return false;
                               }
                             }
                             return true;
                           })) {
      LOG(kError) << "Timed out during waiting response: ";
      for (int n(0); n < size; ++n)
        LOG(kError) << results[n] << " - ";
      return kOperationTimeOut;
    }
  }
  catch(const std::exception &e) {
    LOG(kError) << "Exception Failure during waiting response : " << e.what();
    return kOperationTimeOut;
  }
  return kSuccess;
}

}  // namespace utilities

}  // namespace priv

}  // namespace maidsafe
