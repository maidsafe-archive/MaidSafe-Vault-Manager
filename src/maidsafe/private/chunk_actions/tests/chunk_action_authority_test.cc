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

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/memory_chunk_store.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"
#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_actions/default_rules.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_rules.h"
#include "maidsafe/private/chunk_actions/modifiable_by_owner_rules.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace test {

class ChunkActionAuthorityTest: public testing::Test {
 public:
  ChunkActionAuthorityTest()
      : chunk_store_(),
        chunk_action_authority_() {
    chunk_action_authority_.reset(
        new chunk_actions::ChunkActionAuthority(chunk_store_));
    }
  ~ChunkActionAuthorityTest() {}

 protected:
  void SetUp() {}
  void TearDown() {}

  std::shared_ptr<MemoryChunkStore> chunk_store_;
  std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority_;
};

TEST_F(ChunkActionAuthorityTest, BEH_ValidName) {
}

TEST_F(ChunkActionAuthorityTest, BEH_Cacheable) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidChunk) {
}

TEST_F(ChunkActionAuthorityTest, BEH_Version) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidGet) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidStore) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidDelete) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidModify) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidHas) {
}

}  // namespace test

}  // namespace priv

}  // namespace maidsafe
