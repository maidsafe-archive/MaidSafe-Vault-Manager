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

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_TESTS_MOCK_CHUNK_MANAGER_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_TESTS_MOCK_CHUNK_MANAGER_H_

#include <set>
#include <string>
#include <vector>

#include "gmock/gmock.h"
#include "boost/thread.hpp"

#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/chunk_store.h"
#include "maidsafe/private/chunk_store/chunk_manager.h"
#include "maidsafe/private/return_codes.h"


namespace maidsafe {

namespace priv {

namespace chunk_store {

namespace test {

class MockChunkManager : public priv::chunk_store::ChunkManager {
 public:
  explicit MockChunkManager(
      std::shared_ptr<priv::chunk_store::ChunkStore> chunk_store);
  virtual ~MockChunkManager();

  MOCK_METHOD4(GetChunk, void(const std::string &name,
                              const std::string &local_version,
                              const asymm::Keys &keys,
                              bool lock));

  MOCK_METHOD2(StoreChunk, void(const std::string &chunk_name,
                              const asymm::Keys &keys));

  MOCK_METHOD3(ModifyChunk, void(const std::string &name,
                                 const std::string &content,
                              const asymm::Keys &keys));

  MOCK_METHOD2(DeleteChunk, void(const std::string &chunk_name,
                              const asymm::Keys &keys));

  int64_t StorageSize() {
    return chunk_store()->Size();
  }

  int64_t StorageCapacity() {
    return chunk_store()->Capacity();
  }

  void Timeout() {
    // do nothing, causing an eventual timeout
  }
  void StoreChunkPass(const std::string &chunk_name) {
    chunk_store()->Store(chunk_name, RandomString(128));
    (*sig_chunk_stored_)(chunk_name, kSuccess);
  }

 private:
  MockChunkManager &operator=(const MockChunkManager&);
  MockChunkManager(const MockChunkManager&);
  boost::thread_group thread_group_;
};

}  // namespace test

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_TESTS_MOCK_CHUNK_MANAGER_H_
