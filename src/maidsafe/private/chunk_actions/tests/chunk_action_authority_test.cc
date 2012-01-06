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
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/return_codes.h"

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
        content_(RandomString(100)),
        hash_name_(crypto::Hash<crypto::SHA512>(content_)),
        key_(),
        key1_(),
        signature_(),
        signed_data_(),
        chunk_action_authority_() {
    chunk_action_authority_.reset(
        new ChunkActionAuthority(chunk_store_));
    }
  ~ChunkActionAuthorityTest() {}

 protected:
  void SetUp() {
    ASSERT_EQ(kSuccess, GenerateKeyPair(&key_));
    ASSERT_EQ(kSuccess, GenerateKeyPair(&key1_));
    rsa::Sign(content_, key_.private_key, &signature_);
    signed_data_.set_data(content_);
    signed_data_.set_signature(signature_);
    fs::create_directories(chunk_dir_);
    chunk_store_->Init(chunk_dir_);
  }
  void TearDown() {}

  std::string ComposeAppendableByAllPacketContent() {
    chunk_actions::SignedData signed_allow_others_to_append;
    std::string allow_others_to_append_signature;
    std::string allow_others_to_append(RandomString(1));
    rsa::Sign(allow_others_to_append, key_.private_key,
              &allow_others_to_append_signature);
    signed_allow_others_to_append.set_data(allow_others_to_append);
    signed_allow_others_to_append.set_signature(
                                      allow_others_to_append_signature);

    chunk_actions::AppendableByAll appendable_by_all_chunk;
    appendable_by_all_chunk.mutable_identity_key()->CopyFrom(signed_data_);
    appendable_by_all_chunk.mutable_allow_others_to_append()
                                ->CopyFrom(signed_allow_others_to_append);
    appendable_by_all_chunk.add_appendices()->CopyFrom(signed_data_);
    return appendable_by_all_chunk.SerializeAsString();
  }

  void ValidStoreTests(const std::string &name, const std::string &content) {
    EXPECT_EQ(kInvalidSignedData,
              chunk_action_authority_->ValidStore(name, "",
                                                  key_.public_key));
    EXPECT_EQ(kInvalidPublicKey,
              chunk_action_authority_->ValidStore(name, content,
                                                  rsa::PublicKey()));
    EXPECT_EQ(kSignatureVerificationFailure,
              chunk_action_authority_->ValidStore(name, content,
                                                  key1_.public_key));
    EXPECT_EQ(kSuccess,
              chunk_action_authority_->ValidStore(name, content,
                                                  key_.public_key));
    // tests for the chunk already exists
    chunk_store_->Store(name, content);
    EXPECT_EQ(kKeyNotUnique,
              chunk_action_authority_->ValidStore(name, content,
                                                  key_.public_key));
  }

  std::shared_ptr<fs::path> test_dir_;
  fs::path chunk_dir_;
  std::shared_ptr<FileChunkStore> chunk_store_;
  std::string content_;
  std::string hash_name_;
  rsa::Keys key_;
  rsa::Keys key1_;
  std::string signature_;
  chunk_actions::SignedData signed_data_;
  std::shared_ptr<ChunkActionAuthority> chunk_action_authority_;
};

TEST_F(ChunkActionAuthorityTest, BEH_ValidName_Cacheable) {
  std::string default_type(hash_name_);
  std::string appendable_by_all(hash_name_);
  std::string modifiable_by_owner(hash_name_);
  std::string signature_packet(hash_name_);
  std::string next_type(hash_name_);
  std::string wrong_length_long(hash_name_);
  std::string wrong_length_short(hash_name_);

  appendable_by_all.append(1, chunk_actions::kAppendableByAll);
  modifiable_by_owner.append(1, chunk_actions::kModifiableByOwner);
  signature_packet.append(1, chunk_actions::kSignaturePacket);
  next_type.append(1, 4);
  wrong_length_long.append(3, 9);
  wrong_length_short.erase(0, 1);

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

TEST_F(ChunkActionAuthorityTest, BEH_ValidStore) {
  EXPECT_EQ(kInvalidChunkType,
            chunk_action_authority_->ValidStore("", content_,
                                                key_.public_key));
  EXPECT_EQ(kInvalidChunkType,
            chunk_action_authority_->ValidStore(RandomString(512), content_,
                                                key_.public_key));
  EXPECT_EQ(kInvalidChunkType,
            chunk_action_authority_->ValidStore(RandomString(513), content_,
                                                key_.public_key));
  // tests for DefaultTypePacket
  EXPECT_EQ(kNotHashable,
            chunk_action_authority_->ValidStore(hash_name_, "",
                                                key_.public_key));
  EXPECT_EQ(kNotHashable,
            chunk_action_authority_->ValidStore(hash_name_, RandomString(50),
                                                key_.public_key));
  EXPECT_EQ(kInvalidPublicKey,
            chunk_action_authority_->ValidStore(hash_name_, content_,
                                                rsa::PublicKey()));
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidStore(hash_name_, content_,
                                                key_.public_key));
  chunk_store_->Store(hash_name_, RandomString(50));
  EXPECT_EQ(kInvalidSignedData,
            chunk_action_authority_->ValidStore(hash_name_, content_,
                                                key_.public_key));
  // tests for AppendableByAllPacket
  std::string appendable_by_all_name(hash_name_);
  appendable_by_all_name.append(1, chunk_actions::kAppendableByAll);
  std::string appendable_by_all_content(ComposeAppendableByAllPacketContent());
  ValidStoreTests(appendable_by_all_name, appendable_by_all_content);

  // tests for SignaturePacket
  std::string signature_content(signed_data_.SerializeAsString());
  std::string signature_name(crypto::Hash<crypto::SHA512>(
                              signed_data_.data() + signed_data_.signature()));
  signature_name.append(1, chunk_actions::kSignaturePacket);

  std::string fake_name(crypto::Hash<crypto::SHA512>(RandomString(50)));
  fake_name.append(1, chunk_actions::kSignaturePacket);
  EXPECT_EQ(kNotHashable, chunk_action_authority_->ValidStore(
      fake_name, signature_content, key_.public_key));

  ValidStoreTests(signature_name, signature_content);

  // tests for ModifiableByOwnerPacket
  std::string modifiable_by_owner_content(signed_data_.SerializeAsString());
  std::string modifiable_by_owner_name(hash_name_);
  modifiable_by_owner_name.append(1, chunk_actions::kModifiableByOwner);
  ValidStoreTests(modifiable_by_owner_name, modifiable_by_owner_content);
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidChunk) {
}

TEST_F(ChunkActionAuthorityTest, BEH_Version) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidGet) {
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
