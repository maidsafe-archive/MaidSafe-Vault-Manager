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
#include "maidsafe/private/chunk_actions/utils.h"
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

  chunk_actions::SignedData ComposeSignedData(const rsa::Keys &keys) {
    chunk_actions::SignedData signed_data;
    std::string signature;
    std::string data(RandomString(1));
    rsa::Sign(data, keys.private_key, &signature);
    signed_data.set_data(data);
    signed_data.set_signature(signature);
    return signed_data;
  }

  std::string ComposeAppendableByAllPacketContent() {
    chunk_actions::SignedData signed_allow_others_to_append(
                                                  ComposeSignedData(key_));
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

  void ValidChunkTests(const std::string &name, const std::string &content) {
    EXPECT_FALSE(chunk_action_authority_->ValidChunk(name));
    // tests for the chunk already exists
    chunk_store_->Store(name, content);
    EXPECT_TRUE(chunk_action_authority_->ValidChunk(name));
  }

  void ValidHasTests(const std::string &name, const std::string &content) {
    EXPECT_EQ(kFailedToFindChunk,
              chunk_action_authority_->ValidHas(name, "", key_.public_key));
    // tests for the chunk already exists
    chunk_store_->Store(name, content);
    EXPECT_EQ(kSuccess,
              chunk_action_authority_->ValidHas(name, "", key_.public_key));
  }

  void ValidGetTests(const std::string &name, const std::string &content) {
    std::string result_content;
    EXPECT_EQ(kFailedToFindChunk,
              chunk_action_authority_->ValidGet(name, "",
                                                key_.public_key,
                                                &result_content));
    // tests for the chunk already exists
    chunk_store_->Store(name, content);
    EXPECT_EQ(kSuccess,
              chunk_action_authority_->ValidGet(name, "",
                                                key_.public_key,
                                                &result_content));
    EXPECT_EQ(content, result_content);
  }

  void ValidDeleteTests(const std::string &name, const std::string &content) {
    EXPECT_EQ(kSuccess,
              chunk_action_authority_->ValidDelete(name, "", "",
                                                   rsa::PublicKey()));
    chunk_store_->Store(name, "content");
    EXPECT_EQ(kGeneralError,
              chunk_action_authority_->ValidDelete(name, "", "",
                                                   rsa::PublicKey()));
    chunk_store_->Modify(name, content);
    EXPECT_EQ(kInvalidPublicKey,
              chunk_action_authority_->ValidDelete(name, "", "",
                                                   rsa::PublicKey()));
    EXPECT_EQ(kSignatureVerificationFailure,
              chunk_action_authority_->ValidDelete(name, "", "",
                                                   key1_.public_key));
    EXPECT_EQ(kNotOwner,
              chunk_action_authority_->ValidDelete(name, "", RandomString(50),
                                                   key_.public_key));
    chunk_actions::SignedData fake_signed_data(ComposeSignedData(key1_));
    std::string fake_ownership(fake_signed_data.SerializeAsString());
    EXPECT_EQ(kNotOwner,
              chunk_action_authority_->ValidDelete(name, "", fake_ownership,
                                                   key_.public_key));
    chunk_actions::SignedData signed_data(ComposeSignedData(key_));
    std::string ownership(signed_data.SerializeAsString());
    EXPECT_EQ(kSuccess,
              chunk_action_authority_->ValidDelete(name, "", ownership,
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
  // tests for DefaultTypePacket
  ValidChunkTests(hash_name_, content_);
  std::string fake_default_name(hash_name_);
  fake_default_name.replace(0, 4, "####");
  chunk_store_->Store(fake_default_name, content_);
  EXPECT_FALSE(chunk_action_authority_->ValidChunk(fake_default_name));

  // tests for AppendableByAllPacket
  std::string appendable_by_all_name(hash_name_);
  appendable_by_all_name.append(1, chunk_actions::kAppendableByAll);
  std::string appendable_by_all_content(ComposeAppendableByAllPacketContent());
  ValidChunkTests(appendable_by_all_name, appendable_by_all_content);

  // tests for SignaturePacket
  std::string signature_content(signed_data_.SerializeAsString());
  std::string signature_name(crypto::Hash<crypto::SHA512>(
                              signed_data_.data() + signed_data_.signature()));
  signature_name.append(1, chunk_actions::kSignaturePacket);
  ValidChunkTests(signature_name, signature_content);
  std::string fake_signature_name(signature_name);
  fake_signature_name.replace(0, 4, "####");
  chunk_store_->Store(fake_signature_name, content_);
  EXPECT_FALSE(chunk_action_authority_->ValidChunk(fake_signature_name));
  fake_signature_name.replace(0, 4, "????");
  chunk_store_->Store(fake_signature_name, signature_content);
  EXPECT_FALSE(chunk_action_authority_->ValidChunk(fake_signature_name));

  // tests for ModifiableByOwnerPacket
  std::string modifiable_by_owner_content(signed_data_.SerializeAsString());
  std::string modifiable_by_owner_name(hash_name_);
  modifiable_by_owner_name.append(1, chunk_actions::kModifiableByOwner);
  ValidChunkTests(modifiable_by_owner_name, modifiable_by_owner_content);
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidGet) {
  // tests for DefaultTypePacket
  ValidGetTests(hash_name_, content_);

  // tests for AppendableByAllPacket
  std::string appendable_by_all_name(hash_name_);
  appendable_by_all_name.append(1, chunk_actions::kAppendableByAll);
  std::string appendable_by_all_content(ComposeAppendableByAllPacketContent());
  ValidGetTests(appendable_by_all_name, appendable_by_all_content);
  // a success ValidGet shall clean-up the appendices field
  std::string existing_content = chunk_store_->Get(appendable_by_all_name);
  chunk_actions::AppendableByAll current_chunk;
  chunk_actions::ParseProtobuf<chunk_actions::AppendableByAll>(
                        existing_content, &current_chunk);
  EXPECT_EQ(0, current_chunk.appendices_size());

  std::string fake_name(crypto::Hash<crypto::SHA512>(RandomString(50)));
  fake_name.append(1, chunk_actions::kAppendableByAll);
  chunk_store_->Store(fake_name, RandomString(50));
  std::string result_content;
  EXPECT_EQ(kGeneralError,
            chunk_action_authority_->ValidGet(fake_name, "",
                                              key_.public_key,
                                              &result_content));
  EXPECT_EQ(kInvalidPublicKey,
            chunk_action_authority_->ValidGet(appendable_by_all_name, "",
                                              rsa::PublicKey(),
                                              &result_content));
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidGet(appendable_by_all_name, "",
                                              key1_.public_key,
                                              &result_content));
  EXPECT_EQ(current_chunk.identity_key().SerializeAsString(), result_content);

  // tests for SignaturePacket
  std::string signature_content(signed_data_.SerializeAsString());
  std::string signature_name(crypto::Hash<crypto::SHA512>(
                              signed_data_.data() + signed_data_.signature()));
  signature_name.append(1, chunk_actions::kSignaturePacket);
  ValidGetTests(signature_name, signature_content);

  // tests for ModifiableByOwnerPacket
  std::string modifiable_by_owner_content(signed_data_.SerializeAsString());
  std::string modifiable_by_owner_name(hash_name_);
  modifiable_by_owner_name.append(1, chunk_actions::kModifiableByOwner);
  ValidGetTests(modifiable_by_owner_name, modifiable_by_owner_content);
}

TEST_F(ChunkActionAuthorityTest, BEH_Version) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidDelete) {
  // tests for DefaultTypePacket
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidDelete(hash_name_, "", "",
                                                 rsa::PublicKey()));

  // tests for AppendableByAllPacket
  std::string appendable_by_all_name(hash_name_);
  appendable_by_all_name.append(1, chunk_actions::kAppendableByAll);
  std::string appendable_by_all_content(ComposeAppendableByAllPacketContent());
  ValidDeleteTests(appendable_by_all_name, appendable_by_all_content);

  // tests for SignaturePacket
  std::string signature_content(signed_data_.SerializeAsString());
  std::string signature_name(crypto::Hash<crypto::SHA512>(
                              signed_data_.data() + signed_data_.signature()));
  signature_name.append(1, chunk_actions::kSignaturePacket);
  ValidDeleteTests(signature_name, signature_content);

  // tests for ModifiableByOwnerPacket
  std::string modifiable_by_owner_content(signed_data_.SerializeAsString());
  std::string modifiable_by_owner_name(hash_name_);
  modifiable_by_owner_name.append(1, chunk_actions::kModifiableByOwner);
  ValidDeleteTests(modifiable_by_owner_name, modifiable_by_owner_content);
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidModify) {
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidHas) {
  // tests for DefaultTypePacket
  ValidHasTests(hash_name_, content_);

  // tests for AppendableByAllPacket
  std::string appendable_by_all_name(hash_name_);
  appendable_by_all_name.append(1, chunk_actions::kAppendableByAll);
  std::string appendable_by_all_content(ComposeAppendableByAllPacketContent());
  ValidHasTests(appendable_by_all_name, appendable_by_all_content);

  // tests for SignaturePacket
  std::string signature_content(signed_data_.SerializeAsString());
  std::string signature_name(crypto::Hash<crypto::SHA512>(
                              signed_data_.data() + signed_data_.signature()));
  signature_name.append(1, chunk_actions::kSignaturePacket);
  ValidHasTests(signature_name, signature_content);

  // tests for ModifiableByOwnerPacket
  std::string modifiable_by_owner_content(signed_data_.SerializeAsString());
  std::string modifiable_by_owner_name(hash_name_);
  modifiable_by_owner_name.append(1, chunk_actions::kModifiableByOwner);
  ValidHasTests(modifiable_by_owner_name, modifiable_by_owner_content);
}

}  // namespace test

}  // namespace priv

}  // namespace maidsafe
