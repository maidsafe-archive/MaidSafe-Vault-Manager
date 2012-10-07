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

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"

#include "maidsafe/private/chunk_actions/appendable_by_all_pb.h"
#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_type.h"
#include "maidsafe/private/chunk_actions/utils.h"

#include "maidsafe/private/chunk_store/file_chunk_store.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_actions {

namespace test {

namespace {

SignedData ComposeSignedData(const asymm::Keys& keys, std::string data = RandomString(50)) {
  SignedData signed_data;
  asymm::Signature signature(asymm::Sign(asymm::PlainText(data), keys.private_key));
  signed_data.set_data(data);
  signed_data.set_signature(signature.string());
  return signed_data;
}

}  // unnamed namespace


class ChunkActionAuthorityTest: public testing::Test {
 public:
  ChunkActionAuthorityTest()
      : test_dir_(maidsafe::test::CreateTestPath("MaidSafe_TestCAA")),
        chunk_dir_(*test_dir_ / "chunks"),
        chunk_store_(new chunk_store::FileChunkStore),
        default_content_(RandomString(100)),
        default_name_(crypto::Hash<crypto::SHA512>(default_content_)),
        appendable_by_all_name_(ApplyTypeToName(NodeId(default_name_.string()),
                                                ChunkType::kAppendableByAll)),
        appendable_by_all_content_(),
        signature_name_(),
        signature_content_(),
        modifiable_by_owner_name_(ApplyTypeToName(NodeId(default_name_.string()),
                                                  ChunkType::kModifiableByOwner)),
        modifiable_by_owner_content_(),
        key_(asymm::GenerateKeyPair()),
        key1_(asymm::GenerateKeyPair()),
        signature_(),
        signed_data_(ComposeSignedData(key_, default_content_)),
        invalid_type_name_(default_name_.string() + 'z'),
        chunk_action_authority_(new ChunkActionAuthority(chunk_store_)) {}
  ~ChunkActionAuthorityTest() {}

 protected:
  void SetUp() {
    appendable_by_all_content_ = ComposeAppendableByAllPacketContent(true);
    asymm::EncodedPublicKey encoded_public_key(asymm::EncodeKey(key_.public_key));
    SignedData sd(ComposeSignedData(key_, encoded_public_key.string()));
    signature_name_ =
        ApplyTypeToName(NodeId(crypto::Hash<crypto::SHA512>(sd.data() + sd.signature())),
                        ChunkType::kSignaturePacket);
    signature_content_ = sd.SerializeAsString();
    modifiable_by_owner_content_ = signed_data_.SerializeAsString();
    fs::create_directories(chunk_dir_);
    chunk_store_->Init(chunk_dir_);
  }

  void TearDown() {}

  std::string ComposeAppendableByAllPacketContent(bool valid) {
    std::string appendability_string(1,
        static_cast<char>(valid ? ChunkType::kAppendableByAll : ChunkType::kModifiableByOwner));
    SignedData signed_allow_others_to_append(ComposeSignedData(key_, appendability_string));
    AppendableByAll appendable_by_all_chunk;
    appendable_by_all_chunk.mutable_identity_key()->CopyFrom(signed_data_);
    appendable_by_all_chunk.mutable_allow_others_to_append()->CopyFrom(
        signed_allow_others_to_append);
    appendable_by_all_chunk.add_appendices()->CopyFrom(signed_data_);
    return appendable_by_all_chunk.SerializeAsString();
  }

  std::string ComposeModifyAppendableByAllPacket(bool has_appendability,
                                                 const asymm::Keys& appendability_keys,
                                                 char appendability,
                                                 bool has_identity,
                                                 const asymm::Keys& identity_keys,
                                                 const std::string& indentity) {
    ModifyAppendableByAll modify_appendable_by_all_chunk;
    if (has_appendability) {
      std::string appendability_string(1, appendability);
      SignedData signed_allow_others_to_append(ComposeSignedData(appendability_keys,
                                                                 appendability_string));
      modify_appendable_by_all_chunk.mutable_allow_others_to_append()->CopyFrom(
          signed_allow_others_to_append);
    }
    if (has_identity) {
      SignedData signed_identity_key(ComposeSignedData(identity_keys, indentity));
      modify_appendable_by_all_chunk.mutable_identity_key()->CopyFrom(signed_identity_key);
    }
    return modify_appendable_by_all_chunk.SerializeAsString();
  }

  void ValidStoreTests(const ChunkId& name, const std::string& content) {
    EXPECT_EQ(kInvalidSignedData, chunk_action_authority_->ValidStore(name, "", key_.public_key));
    if (GetChunkType(name) == ChunkType::kSignaturePacket)
      EXPECT_EQ(kSuccess, chunk_action_authority_->ValidStore(name, content, asymm::PublicKey()));
    else
      EXPECT_EQ(kSignatureCheckError,
                chunk_action_authority_->ValidStore(name, content, asymm::PublicKey()));
    EXPECT_EQ(kFailedSignatureCheck,
              chunk_action_authority_->ValidStore(name, content, key1_.public_key));
    EXPECT_EQ(kSuccess, chunk_action_authority_->ValidStore(name, content, key_.public_key));
    // tests for the chunk already exists
    chunk_store_->Store(name, content);
    EXPECT_EQ(kKeyNotUnique, chunk_action_authority_->ValidStore(name, content, key_.public_key));
  }

  void ValidChunkTests(const ChunkId& name, const std::string& content) {
    EXPECT_FALSE(chunk_action_authority_->ValidChunk(name));
    // tests for the chunk already exists
    chunk_store_->Store(name, content);
    EXPECT_TRUE(chunk_action_authority_->ValidChunk(name));
  }

  void ValidHasTests(const ChunkId& name, const std::string& content) {
    EXPECT_EQ(kFailedToFindChunk,
              chunk_action_authority_->ValidHas(name, ChunkVersion(), key_.public_key));
    // tests for the chunk already exists
    chunk_store_->Store(name, content);
    EXPECT_EQ(kSuccess, chunk_action_authority_->ValidHas(name, ChunkVersion(), key_.public_key));
  }

  void ValidGetTests(const ChunkId& name, const std::string& content) {
    std::string result_content;
    EXPECT_EQ(kFailedToFindChunk, chunk_action_authority_->ValidGet(name,
                                                                    ChunkVersion(),
                                                                    key_.public_key,
                                                                    &result_content));
    // tests for the chunk already exists
    chunk_store_->Store(name, content);
    EXPECT_EQ(kSuccess, chunk_action_authority_->ValidGet(name,
                                                          ChunkVersion(),
                                                          key_.public_key,
                                                          &result_content));
    EXPECT_EQ(content, result_content);
  }

  void ValidDeleteTests(const ChunkId& name, const std::string& content) {
    EXPECT_EQ(kSuccess, chunk_action_authority_->ValidDelete(name, "", asymm::PublicKey()));
    chunk_store_->Store(name, "content");
    EXPECT_EQ(kParseFailure, chunk_action_authority_->ValidDelete(name, "", asymm::PublicKey()));
    chunk_store_->Modify(name, content);
    EXPECT_EQ(kFailedSignatureCheck,
              chunk_action_authority_->ValidDelete(name, "", asymm::PublicKey()));
    EXPECT_EQ(kFailedSignatureCheck,
              chunk_action_authority_->ValidDelete(name, "", key1_.public_key));
    EXPECT_EQ(kNotOwner,
              chunk_action_authority_->ValidDelete(name, RandomString(50), key_.public_key));
    SignedData fake_signed_data(ComposeSignedData(key1_));
    std::string fake_ownership(fake_signed_data.SerializeAsString());
    EXPECT_EQ(kNotOwner,
              chunk_action_authority_->ValidDelete(name, fake_ownership, key_.public_key));
    std::string ownership(signed_data_.SerializeAsString());
    EXPECT_EQ(kSuccess,
              chunk_action_authority_->ValidDelete(name, ownership, key_.public_key));
  }

  void DeleteTests(const ChunkId& name, const std::string& content) {
    // detailed validation tests have been undertaken in the tests of
    // ValidDelete, so here we only need to check if chunk_store works well
    chunk_store_->Store(name, content);
    std::string ownership(signed_data_.SerializeAsString());
    EXPECT_TRUE(chunk_action_authority_->Delete(name, ownership, key_.public_key));
    std::string result(chunk_store_->Get(name));
    EXPECT_TRUE(result.empty());
  }

  size_t ValidModifyTests(const ChunkId& name, const std::string& content) {
    int64_t size_difference(10);
    std::string new_content;
    EXPECT_EQ(kNullParameter,
              chunk_action_authority_->ValidModify(name, "", asymm::PublicKey(), nullptr));
    EXPECT_EQ(kFailedToFindChunk,
              chunk_action_authority_->ValidModify(name,
                                                   "",
                                                   asymm::PublicKey(),
                                                   &size_difference,
                                                   &new_content));
    EXPECT_EQ(0, size_difference);
    size_difference = 10;
    std::string original_data("content");
    EXPECT_TRUE(chunk_store_->Store(name, original_data));
    EXPECT_EQ(kParseFailure,
              chunk_action_authority_->ValidModify(name,
                                                   "",
                                                   asymm::PublicKey(),
                                                   &size_difference,
                                                   &new_content));
    EXPECT_EQ(0, size_difference);
    size_difference = 10;
    EXPECT_TRUE(chunk_store_->Modify(name, content));
    EXPECT_EQ(kFailedSignatureCheck,
              chunk_action_authority_->ValidModify(name,
                                                   "",
                                                   asymm::PublicKey(),
                                                   &size_difference,
                                                   &new_content));
    EXPECT_EQ(0, size_difference);
    size_difference = 10;
    return content.size();
  }

  void VersionTests(const ChunkId& name, bool hashable) {
    ChunkVersion result(chunk_action_authority_->Version(name));
    if (hashable)
      EXPECT_TRUE(result.IsInitialised());
    else
      EXPECT_FALSE(result.IsInitialised());
    std::string content(RandomString(20));
    chunk_store_->Store(name, content);
    result = chunk_action_authority_->Version(name);
    if (hashable)
      EXPECT_EQ(result.string(), name.string().substr(0, crypto::Tiger::DIGESTSIZE));
    else
      EXPECT_EQ(result, crypto::Hash<crypto::Tiger>(content));
  }

  std::shared_ptr<fs::path> test_dir_;
  fs::path chunk_dir_;
  std::shared_ptr<chunk_store::FileChunkStore> chunk_store_;
  std::string default_content_;
  ChunkId default_name_;
  ChunkId appendable_by_all_name_;
  std::string appendable_by_all_content_;
  ChunkId signature_name_;
  std::string signature_content_;
  ChunkId modifiable_by_owner_name_;
  std::string modifiable_by_owner_content_;
  asymm::Keys key_;
  asymm::Keys key1_;
  asymm::Signature signature_;
  SignedData signed_data_;
  ChunkId invalid_type_name_;
  std::shared_ptr<ChunkActionAuthority> chunk_action_authority_;
};

TEST_F(ChunkActionAuthorityTest, BEH_ValidName) {
  EXPECT_TRUE(chunk_action_authority_->ValidName(default_name_));
  EXPECT_TRUE(chunk_action_authority_->ValidName(appendable_by_all_name_));
  EXPECT_TRUE(chunk_action_authority_->ValidName(modifiable_by_owner_name_));
  EXPECT_TRUE(chunk_action_authority_->ValidName(signature_name_));
  EXPECT_FALSE(chunk_action_authority_->ValidName(invalid_type_name_));
}

TEST_F(ChunkActionAuthorityTest, BEH_Cacheable) {
  EXPECT_TRUE(chunk_action_authority_->Cacheable(default_name_));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(appendable_by_all_name_));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(modifiable_by_owner_name_));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(signature_name_));
  EXPECT_FALSE(chunk_action_authority_->Cacheable(invalid_type_name_));
}

TEST_F(ChunkActionAuthorityTest, BEH_Modifiable) {
  EXPECT_FALSE(chunk_action_authority_->Modifiable(default_name_));
  EXPECT_TRUE(chunk_action_authority_->Modifiable(appendable_by_all_name_));
  EXPECT_TRUE(chunk_action_authority_->Modifiable(modifiable_by_owner_name_));
  EXPECT_FALSE(chunk_action_authority_->Modifiable(signature_name_));
  EXPECT_FALSE(chunk_action_authority_->Modifiable(invalid_type_name_));
}

TEST_F(ChunkActionAuthorityTest, BEH_ModifyReplaces) {
  EXPECT_FALSE(chunk_action_authority_->ModifyReplaces(default_name_));
  EXPECT_FALSE(chunk_action_authority_->ModifyReplaces(appendable_by_all_name_));
  EXPECT_TRUE(chunk_action_authority_->ModifyReplaces(modifiable_by_owner_name_));
  EXPECT_FALSE(chunk_action_authority_->ModifyReplaces(signature_name_));
  EXPECT_FALSE(chunk_action_authority_->ModifyReplaces(invalid_type_name_));
}

TEST_F(ChunkActionAuthorityTest, BEH_Payable) {
  EXPECT_TRUE(chunk_action_authority_->Payable(default_name_));
  EXPECT_FALSE(chunk_action_authority_->Payable(appendable_by_all_name_));
  EXPECT_FALSE(chunk_action_authority_->Payable(modifiable_by_owner_name_));
  EXPECT_FALSE(chunk_action_authority_->Payable(signature_name_));
  EXPECT_FALSE(chunk_action_authority_->Payable(invalid_type_name_));
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidStore) {
  EXPECT_EQ(kInvalidChunkType, chunk_action_authority_->ValidStore(invalid_type_name_,
                                                                   default_content_,
                                                                   key_.public_key));
  // tests for DefaultTypePacket
  EXPECT_EQ(kNotHashable,
            chunk_action_authority_->ValidStore(default_name_, "", key_.public_key));
  EXPECT_EQ(kNotHashable,
            chunk_action_authority_->ValidStore(default_name_, RandomString(50), key_.public_key));
  /* EXPECT_EQ(kInvalidPublicKey,
            chunk_action_authority_->ValidStore(default_name_, default_content_,
                                                asymm::PublicKey())); */
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidStore(default_name_, default_content_, key_.public_key));
  chunk_store_->Store(default_name_, RandomString(50));
  EXPECT_EQ(kInvalidSignedData,
            chunk_action_authority_->ValidStore(default_name_, default_content_, key_.public_key));
  // tests for AppendableByAllPacket
  ValidStoreTests(appendable_by_all_name_, appendable_by_all_content_);

  // tests for SignaturePacket
  ChunkId fake_name(ApplyTypeToName(NodeId(crypto::Hash<crypto::SHA512>(RandomString(50))),
                    ChunkType::kSignaturePacket));
  EXPECT_EQ(kNotHashable,
            chunk_action_authority_->ValidStore(fake_name, signature_content_, key_.public_key));
  SignedData signed_data(ComposeSignedData(key_));
  fake_name = ApplyTypeToName(NodeId(crypto::Hash<crypto::SHA512>(signed_data.data() +
                                                                  signed_data.signature())),
                              ChunkType::kSignaturePacket);
  EXPECT_EQ(kDataNotPublicKey, chunk_action_authority_->ValidStore(fake_name,
                                                                   signed_data.SerializeAsString(),
                                                                   key_.public_key));

  ValidStoreTests(signature_name_, signature_content_);

  // tests for ModifiableByOwnerPacket
  ValidStoreTests(modifiable_by_owner_name_, modifiable_by_owner_content_);
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidChunk) {
  // tests for DefaultTypePacket
  ValidChunkTests(default_name_, default_content_);
  std::string fake_default_name(default_name_.string());
  fake_default_name.replace(0, 4, "####");
  chunk_store_->Store(ChunkId(fake_default_name), default_content_);
  EXPECT_FALSE(chunk_action_authority_->ValidChunk(ChunkId(fake_default_name)));

  // tests for AppendableByAllPacket
  ValidChunkTests(appendable_by_all_name_, appendable_by_all_content_);

  // tests for SignaturePacket
  ValidChunkTests(signature_name_, signature_content_);
  std::string fake_signature_name(signature_name_.string());
  fake_signature_name.replace(0, 4, "####");
  chunk_store_->Store(ChunkId(fake_signature_name), default_content_);
  EXPECT_FALSE(chunk_action_authority_->ValidChunk(ChunkId(fake_signature_name)));
  fake_signature_name.replace(0, 4, "????");
  chunk_store_->Store(ChunkId(fake_signature_name), signature_content_);
  EXPECT_FALSE(chunk_action_authority_->ValidChunk(ChunkId(fake_signature_name)));

  // tests for ModifiableByOwnerPacket
  ValidChunkTests(modifiable_by_owner_name_, modifiable_by_owner_content_);
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidGet) {
  // tests for DefaultTypePacket
  ValidGetTests(default_name_, default_content_);

  // tests for AppendableByAllPacket
  ValidGetTests(appendable_by_all_name_, appendable_by_all_content_);
  std::string existing_content = chunk_store_->Get(appendable_by_all_name_);
  AppendableByAll current_chunk;
  detail::ParseProtobuf<AppendableByAll>(existing_content, &current_chunk);
  EXPECT_EQ(0, current_chunk.appendices_size());
  ChunkId fake_name(ApplyTypeToName(NodeId(crypto::Hash<crypto::SHA512>(RandomString(50))),
                    ChunkType::kAppendableByAll));
  chunk_store_->Store(fake_name, RandomString(50));
  std::string result_content;
  EXPECT_EQ(kParseFailure,
            chunk_action_authority_->ValidGet(fake_name, ChunkVersion(),
                                              key_.public_key,
                                              &result_content));
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidGet(appendable_by_all_name_, ChunkVersion(),
                                              asymm::PublicKey(),
                                              &result_content));
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidGet(appendable_by_all_name_, ChunkVersion(),
                                              key1_.public_key,
                                              &result_content));
  current_chunk.Clear();
  detail::ParseProtobuf<AppendableByAll>(appendable_by_all_content_, &current_chunk);
  EXPECT_EQ(current_chunk.identity_key().SerializeAsString(), result_content);

  // tests for SignaturePacket
  ValidGetTests(signature_name_, signature_content_);

  // tests for ModifiableByOwnerPacket
  ValidGetTests(modifiable_by_owner_name_, modifiable_by_owner_content_);
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidDelete) {
  // tests for DefaultTypePacket
  EXPECT_EQ(kSuccess, chunk_action_authority_->ValidDelete(default_name_, "", asymm::PublicKey()));

  // tests for AppendableByAllPacket
  ValidDeleteTests(appendable_by_all_name_, appendable_by_all_content_);

  // tests for SignaturePacket
  ValidDeleteTests(signature_name_, signature_content_);

  // tests for ModifiableByOwnerPacket
  ValidDeleteTests(modifiable_by_owner_name_, modifiable_by_owner_content_);
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidModify) {
  // tests for DefaultTypePacket
  int64_t size_difference;
  EXPECT_EQ(kInvalidModify,
            chunk_action_authority_->ValidModify(default_name_, "", asymm::PublicKey(),
                                                 &size_difference));

  // tests for AppendableByAllPacket
  size_t previous_size(ValidModifyTests(appendable_by_all_name_, appendable_by_all_content_));
  std::string response_content;
  // ensure random data doesn't happen to parse as an AppendableByAll chunk
  std::string random_data(RandomString(10));
  ModifyAppendableByAll chunk;
  while (detail::ParseProtobuf<ModifyAppendableByAll>(random_data, &chunk))
    random_data = RandomString(10);
  // being owner
  EXPECT_EQ(kInvalidSignedData,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                                                 random_data,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &response_content));
  asymm::Keys appendability_key(asymm::GenerateKeyPair());
  asymm::Keys identity_key(asymm::GenerateKeyPair());
  std::string identity(RandomString(50));
  std::string non_control_content(ComposeModifyAppendableByAllPacket(false, appendability_key,
      static_cast<char>(ChunkType::kModifiableByOwner), false, identity_key, identity));
  EXPECT_EQ(kInvalidModify,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                                                 non_control_content,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &response_content));
  std::string both_control_content(ComposeModifyAppendableByAllPacket(true, appendability_key,
      static_cast<char>(ChunkType::kModifiableByOwner), true, identity_key, identity));
  EXPECT_EQ(kInvalidModify,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                                                 both_control_content,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &response_content));
  std::string fake_appendability_only(ComposeModifyAppendableByAllPacket(true, appendability_key,
      static_cast<char>(ChunkType::kModifiableByOwner), false, identity_key, identity));
  EXPECT_EQ(kFailedSignatureCheck,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                                                 fake_appendability_only,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &response_content));
  std::string fake_identity_only(ComposeModifyAppendableByAllPacket(false, appendability_key,
      static_cast<char>(ChunkType::kModifiableByOwner), true, identity_key, identity));
  EXPECT_EQ(kFailedSignatureCheck,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                                                 fake_identity_only,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &response_content));
  std::string appendability_only(ComposeModifyAppendableByAllPacket(true, key_,
      static_cast<char>(ChunkType::kModifiableByOwner), false, key_, identity));
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                                                 appendability_only,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &response_content));
  EXPECT_EQ(static_cast<int64_t>(previous_size - response_content.size()), size_difference);
  AppendableByAll appendability_response_chunk;
  detail::ParseProtobuf<AppendableByAll>(response_content, &appendability_response_chunk);
  std::string response_appendability(1, static_cast<char>(ChunkType::kModifiableByOwner));
  EXPECT_EQ(response_appendability, appendability_response_chunk.allow_others_to_append().data());
  std::string identity_only(ComposeModifyAppendableByAllPacket( false, key_,
      static_cast<char>(ChunkType::kModifiableByOwner), true, key_, identity));
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                                                 identity_only,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &response_content));
  EXPECT_EQ(static_cast<int64_t>(previous_size - response_content.size()),
            size_difference);
  AppendableByAll identity_response_chunk;
  detail::ParseProtobuf<AppendableByAll>(response_content, &identity_response_chunk);
  EXPECT_EQ(identity, identity_response_chunk.identity_key().data());
  // being non-owner
  EXPECT_EQ(kFailedSignatureCheck,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                    signed_data_.SerializeAsString(),
                    key1_.public_key, &size_difference, &response_content));
  SignedData new_signed_data(ComposeSignedData(key1_));
  std::string new_data(new_signed_data.SerializeAsString());
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidModify(appendable_by_all_name_,
                                                 new_data,
                                                 key1_.public_key,
                                                 &size_difference,
                                                 &response_content));
  EXPECT_EQ(static_cast<int64_t>(previous_size) - response_content.size(), size_difference);
  AppendableByAll new_chunk;
  detail::ParseProtobuf<AppendableByAll>(response_content, &new_chunk);
  EXPECT_EQ(2, new_chunk.appendices_size());

  std::string diallowed_appendable_by_all_content(ComposeAppendableByAllPacketContent(false));
  chunk_store_->Modify(appendable_by_all_name_, diallowed_appendable_by_all_content);
  previous_size = diallowed_appendable_by_all_content.size();
  EXPECT_EQ(kAppendDisallowed,
            chunk_action_authority_->ValidModify(appendable_by_all_name_, "",
                                                 key1_.public_key,
                                                 &size_difference,
                                                 &response_content));

  // tests for SignaturePacket
  EXPECT_EQ(kInvalidModify,
            chunk_action_authority_->ValidModify(signature_name_, "",
                                                 asymm::PublicKey(),
                                                 &size_difference));
  // tests for ModifiableByOwnerPacket
  previous_size = ValidModifyTests(modifiable_by_owner_name_, modifiable_by_owner_content_);
  std::string new_content;
  EXPECT_EQ(kNotOwner,
            chunk_action_authority_->ValidModify(modifiable_by_owner_name_, "",
                                                 key1_.public_key,
                                                 &size_difference,
                                                 &new_content));
  EXPECT_EQ(kInvalidSignedData,
            chunk_action_authority_->ValidModify(modifiable_by_owner_name_,
                                                 RandomString(50),
                                                 key_.public_key,
                                                 &size_difference,
                                                 &new_content));
  std::string fake_signed_data(ComposeSignedData(key1_).SerializeAsString());
  EXPECT_EQ(kFailedSignatureCheck,
            chunk_action_authority_->ValidModify(modifiable_by_owner_name_,
                                                 fake_signed_data,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &new_content));
  std::string signed_data(ComposeSignedData(key_).SerializeAsString());
  EXPECT_EQ(kSuccess,
            chunk_action_authority_->ValidModify(modifiable_by_owner_name_,
                                                 signed_data,
                                                 key_.public_key,
                                                 &size_difference,
                                                 &new_content));
  EXPECT_EQ(static_cast<int64_t>(previous_size - new_content.size()), size_difference);
  EXPECT_EQ(new_content, signed_data);
}

TEST_F(ChunkActionAuthorityTest, BEH_ValidHas) {
  // tests for DefaultTypePacket
  ValidHasTests(default_name_, default_content_);

  // tests for AppendableByAllPacket
  ValidHasTests(appendable_by_all_name_, appendable_by_all_content_);

  // tests for SignaturePacket
  ValidHasTests(signature_name_, signature_content_);

  // tests for ModifiableByOwnerPacket
  ValidHasTests(modifiable_by_owner_name_, modifiable_by_owner_content_);
}

TEST_F(ChunkActionAuthorityTest, BEH_Version) {
  // if hashable, then return the name, otherwise return tigerhash of content
  // tests for DefaultTypePacket
  VersionTests(default_name_, true);

  // tests for AppendableByAllPacket
  VersionTests(appendable_by_all_name_, false);

  // tests for SignaturePacket
  VersionTests(signature_name_, true);

  // tests for ModifiableByOwnerPacket
  VersionTests(modifiable_by_owner_name_, false);
}

TEST_F(ChunkActionAuthorityTest, BEH_Delete) {
  // tests for DefaultTypePacket, will always return success
  EXPECT_TRUE(chunk_action_authority_->Delete(default_name_, "",
                                              asymm::PublicKey()));

  // tests for AppendableByAllPacket
  DeleteTests(appendable_by_all_name_, appendable_by_all_content_);

  // tests for SignaturePacket
  DeleteTests(signature_name_, signature_content_);

  // tests for ModifiableByOwnerPacket
  DeleteTests(modifiable_by_owner_name_, modifiable_by_owner_content_);
}

}  // namespace test

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe
