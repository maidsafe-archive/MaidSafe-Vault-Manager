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

#include <memory>

#include "maidsafe/private/chunk_store/memory_chunk_store.h"
#include "maidsafe/private/chunk_store/tests/chunk_store_api_test.h"

namespace maidsafe {

namespace priv {

namespace chunk_store {

namespace test {

template <>
void ChunkStoreTest<MemoryChunkStore>::InitChunkStore(std::shared_ptr<ChunkStore>* chunk_store,
                                                      const fs::path&,
                                                      boost::asio::io_service&) {
  chunk_store->reset(new MemoryChunkStore());
}

INSTANTIATE_TYPED_TEST_CASE_P(Memory, ChunkStoreTest, MemoryChunkStore);

}  // namespace test

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
