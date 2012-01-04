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

#include "boost/asio/io_service.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/file_chunk_store.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_actions/chunk_types.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace test {

class ChunkActionAuthorityTest: public testing::Test {
 public:
  ChunkActionAuthorityTest()
      : test_dir_(maidsafe::test::CreateTestPath("MaidSafe_TestCAA")),
        chunk_dir_(*test_dir_ / "chunks"),
        chunk_store_(new FileChunkStore),
        chunk_action_authority_() {
    chunk_action_authority_.reset(
        new ChunkActionAuthority(chunk_store_));
    }
  ~ChunkActionAuthorityTest() {}

 protected:
  void SetUp() {
    fs::create_directories(chunk_dir_);
    chunk_store_->Init(chunk_dir_);
  }
  void TearDown() {}

  std::shared_ptr<fs::path> test_dir_;
  fs::path chunk_dir_;
  std::shared_ptr<FileChunkStore> chunk_store_;
  std::shared_ptr<ChunkActionAuthority> chunk_action_authority_;
};

TEST_F(ChunkActionAuthorityTest, BEH_ValidName_Cacheable) {
  std::string base_string(crypto::Hash<crypto::SHA512>(RandomString(100)));
  std::string default_type(base_string);
  std::string appendable_by_all(base_string);
  std::string modifiable_by_owner(base_string);
  std::string signature_packet(base_string);
  std::string next_type(base_string);
  std::string wrong_length_long(base_string);
  std::string wrong_length_short(base_string);

  appendable_by_all.append(1, chunk_actions::kAppendableByAll);
  modifiable_by_owner.append(1, chunk_actions::kModifiableByOwner);
  signature_packet.append(1, chunk_actions::kSignaturePacket);
  next_type.append(1, 4);
  wrong_length_long.append(3, 9);
  wrong_length_short.erase(0,1);

  EXPECT_TRUE(chunk_action_authority_->ValidName(default_type));
  EXPECT_TRUE(chunk_action_authority_->ValidName(appendable_by_all));
  EXPECT_TRUE(chunk_action_authority_->ValidName(modifiable_by_owner));
  EXPECT_TRUE(chunk_action_authority_->ValidName(signature_packet));
  EXPECT_FALSE(chunk_action_authority_->ValidName(next_type));
  EXPECT_FALSE(chunk_action_authority_->ValidName(wrong_length_long));
  EXPECT_FALSE(chunk_action_authority_->ValidName(wrong_length_short));

  EXPECT_TRUE(chunk_action_authority_->Cacheable(default_type));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(appendable_by_all));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(modifiable_by_owner));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(signature_packet));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(next_type));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(wrong_length_long));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(wrong_length_short));
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
