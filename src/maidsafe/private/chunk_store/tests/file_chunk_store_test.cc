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

#include "boost/filesystem.hpp"

#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/file_chunk_store.h"
#include "maidsafe/private/chunk_store/tests/chunk_store_api_test.h"

namespace maidsafe {

namespace priv {

namespace chunk_store {

namespace test {

template <>
void ChunkStoreTest<FileChunkStore>::InitChunkStore(
    std::shared_ptr<ChunkStore> *chunk_store,
    const fs::path &chunk_dir,
    boost::asio::io_service&) {
  chunk_store->reset(new FileChunkStore());
  if (!chunk_dir.empty())
    reinterpret_cast<FileChunkStore*>(chunk_store->get())->Init(chunk_dir);
}

INSTANTIATE_TYPED_TEST_CASE_P(Files, ChunkStoreTest, FileChunkStore);

class FileChunkStoreTest: public testing::Test {
 public:
  FileChunkStoreTest()
      : test_dir_(maidsafe::test::CreateTestPath(
                      "MaidSafe_TestFileChunkStore")),
        chunk_dir_(*test_dir_ / "chunks"),
        ref_chunk_dir_(*test_dir_ / "ref_chunks") {}
  ~FileChunkStoreTest() {}
 protected:
  void SetUp() {
    fs::create_directories(chunk_dir_);
    fs::create_directories(ref_chunk_dir_);
  }

  maidsafe::test::TestPath test_dir_;
  fs::path chunk_dir_, ref_chunk_dir_;
};

TEST_F(FileChunkStoreTest, BEH_Init) {
  //  File chunk store without reference counting
  std::shared_ptr<FileChunkStore> fcs_first(
      new FileChunkStore());

  fs::path chunk_dir_first(*test_dir_ / "chunks_first");
  EXPECT_EQ(true, fcs_first->Init(chunk_dir_first, 10));
  EXPECT_EQ(0, fcs_first->Count());
  EXPECT_TRUE(fcs_first->Empty());
  EXPECT_FALSE(fcs_first->Has(""));
  EXPECT_FALSE(fcs_first->Has("something"));

  //  Reuse existing chunk directory
  std::shared_ptr<FileChunkStore> fcs_second(
      new FileChunkStore());
  EXPECT_TRUE(fcs_second->Init(chunk_dir_first, 10));
  EXPECT_EQ(0, fcs_second->Count());
  EXPECT_TRUE(fcs_second->Empty());
  EXPECT_FALSE(fcs_second->Has(""));
  EXPECT_FALSE(fcs_second->Has("something"));

  //  Test by passing nothing for Dir name
  std::shared_ptr<FileChunkStore> fcs_third(
      new FileChunkStore());
  EXPECT_FALSE(fcs_third->Init("", 10));
  EXPECT_EQ(0, fcs_third->Count());
  EXPECT_TRUE(fcs_third->Empty());
  EXPECT_FALSE(fcs_third->Has(""));
  EXPECT_FALSE(fcs_third->Has("something"));

  //  Test initialiation of reference counted file chunk store
  std::shared_ptr<FileChunkStore> ref_fcs_first(
      new FileChunkStore());
  fs::path ref_chunk_dir_first(*test_dir_ / "ref_chunks_first");
  EXPECT_TRUE(ref_fcs_first->Init(ref_chunk_dir_first, 10));
  EXPECT_EQ(0, ref_fcs_first->Count());
  EXPECT_TRUE(ref_fcs_first->Empty());
  EXPECT_FALSE(ref_fcs_first->Has(""));
  EXPECT_FALSE(ref_fcs_first->Has("something"));

  //  Reuse existing chunk directory
  std::shared_ptr<FileChunkStore> ref_fcs_second(
      new FileChunkStore());
  EXPECT_TRUE(ref_fcs_second->Init(ref_chunk_dir_first, 10));
  EXPECT_EQ(0, ref_fcs_second->Count());
  EXPECT_TRUE(ref_fcs_second->Empty());
  EXPECT_FALSE(ref_fcs_second->Has(""));
  EXPECT_FALSE(ref_fcs_second->Has("something"));

  //  Test by passing nothing for Dir name
  std::shared_ptr<FileChunkStore> ref_fcs_third(
      new FileChunkStore());
  EXPECT_FALSE(ref_fcs_third->Init("", 10));
  EXPECT_EQ(0, ref_fcs_third->Count());
  EXPECT_TRUE(ref_fcs_third->Empty());
  EXPECT_FALSE(ref_fcs_third->Has(""));
  EXPECT_FALSE(ref_fcs_third->Has("something"));
}

TEST_F(FileChunkStoreTest, BEH_Get) {
  std::shared_ptr<FileChunkStore> fcs(
      new FileChunkStore());

  std::string content(RandomString(100));
  std::string name(crypto::Hash<crypto::SHA512>(content));
  fs::path path(*test_dir_ / "chunk.dat");

  //  try to get a chunk without initialising chunk store
  EXPECT_TRUE(fcs->Get("anything").empty());
  EXPECT_FALSE(fcs->Get("some_chunk", path));

  //  initialise
  EXPECT_TRUE(fcs->Init(chunk_dir_, 2));

  //  try getting something non existing
  EXPECT_TRUE(fcs->Get("whatever").empty());

  //  store data
  ASSERT_TRUE(fcs->Store(name, content));

  // existing chunk
  EXPECT_EQ(content, fcs->Get(name));
  EXPECT_TRUE(fcs->Get(name, path));

  //  create a ref counted chunk store
  std::shared_ptr<FileChunkStore> fcs_ref(
      new FileChunkStore());
  EXPECT_EQ(true, fcs_ref->Init(ref_chunk_dir_, 10));
  ASSERT_TRUE(fcs_ref->Store(name, content));
  ASSERT_TRUE(fcs_ref->Store(name, content));
  ASSERT_TRUE(fcs_ref->Store(name, content));

  //  get the chunk
  fs::path sink_path(*test_dir_ / "my_chunk.dat");
  EXPECT_FALSE(fs::exists(sink_path));
  EXPECT_TRUE(fcs_ref->Get(name, sink_path));
}

TEST_F(FileChunkStoreTest, BEH_Store) {
  std::shared_ptr<FileChunkStore> fcs(
      new FileChunkStore());

  std::string content(RandomString(100));
  std::string name(crypto::Hash<crypto::SHA512>(content));

  //  try storing without initialising
  EXPECT_FALSE(fcs->Store(name, content));
  EXPECT_FALSE(fcs->Store(name, fs::path("anypath"), true));
  EXPECT_TRUE(fcs->Init(chunk_dir_, 4));

  //  try storing an empty chunk
  EXPECT_FALSE(fcs->Store("", content));
  EXPECT_FALSE(fcs->Store(name, ""));

  //  try storing a chunk
  EXPECT_TRUE(fcs->Store(name, content));
  //  same one again
  EXPECT_TRUE(fcs->Store(name, content));

  fs::path path(*test_dir_ / "chunk.dat");
  EXPECT_TRUE(fcs->Get(name, path));

  //  reference counted chunk store
  std::shared_ptr<FileChunkStore> ref_fcs(
      new FileChunkStore());
  EXPECT_FALSE(ref_fcs->Store(name, content));

  EXPECT_TRUE(ref_fcs->Init(ref_chunk_dir_, 3));
  fs::path non_existant_file(*test_dir_ / "non_existant");
  EXPECT_FALSE(ref_fcs->Store(name, non_existant_file, true));

  //  store chunks iteratively
  int count = 1000;
  for (int iter = 0; iter < count; ++iter) {
    content = RandomString(500);
    name = crypto::Hash<crypto::SHA512>(content);
    std::string file_name(EncodeToHex(RandomString(10)));
    path = fs::path(*test_dir_ / file_name);

    EXPECT_TRUE(ref_fcs->Store(name, content));
    EXPECT_TRUE(ref_fcs->Get(name, path));
    EXPECT_TRUE(ref_fcs->Store(name, path, true));

    std::string content1(RandomString(500));
    std::string name1(crypto::Hash<crypto::SHA512>(content1));
    std::string file_name1(EncodeToHex(RandomString(10)));
    fs::path path1(*test_dir_ / file_name1);

    EXPECT_TRUE(ref_fcs->Store(name1, content1));
    EXPECT_TRUE(ref_fcs->Get(name1, path1));
    EXPECT_TRUE(ref_fcs->Store(name1, path1, false));
  }

  //  reuse ref_fcs chunk store
  std::shared_ptr<FileChunkStore> reused_fcs(
      new FileChunkStore());
  EXPECT_TRUE(reused_fcs->Init(ref_chunk_dir_, 3));

  std::shared_ptr<FileChunkStore> chunk_store(
      new FileChunkStore());
  EXPECT_TRUE(chunk_store->Init(ref_chunk_dir_, 3));

  content = RandomString(500);
  name = crypto::Hash<crypto::SHA512>(content);
  EXPECT_TRUE(chunk_store->Store(name, content));
}

TEST_F(FileChunkStoreTest, BEH_Capacity) {
  //  create a chunk store with limited capacity
  std::shared_ptr<FileChunkStore> fcs_cap(
      new FileChunkStore());
  EXPECT_TRUE(fcs_cap->Init(ref_chunk_dir_, 4));
  fcs_cap->SetCapacity(100);
  EXPECT_TRUE(fcs_cap->Empty());

  std::string content(RandomString(100));
  std::string name(crypto::Hash<crypto::SHA512>(content));
  std::string file_name("file.dat");
  fs::path path(*test_dir_ / file_name);

  EXPECT_TRUE(fcs_cap->Store(name, content));

  std::string extra_content(RandomString(1));
  std::string extra_content_chunk_name(
                crypto::Hash<crypto::SHA512>(extra_content));
  EXPECT_FALSE(fcs_cap->Store(extra_content_chunk_name, extra_content));

  EXPECT_TRUE(fcs_cap->Get(name, path));
  EXPECT_FALSE(fcs_cap->Store(extra_content_chunk_name, path, true));
}

TEST_F(FileChunkStoreTest, BEH_Delete) {
  std::shared_ptr<FileChunkStore> fcs(
      new FileChunkStore());
  EXPECT_FALSE(fcs->Delete("somechunk"));

  std::shared_ptr<FileChunkStore> ref_fcs(
      new FileChunkStore());
  EXPECT_TRUE(ref_fcs->Init(ref_chunk_dir_, 4));

  std::string content("mycontent");
  std::string name(crypto::Hash<crypto::SHA512>(content));
  EXPECT_TRUE(ref_fcs->Store(name, content));

  //  try deleting non existant chunk
  EXPECT_TRUE(ref_fcs->Delete("unknownchunk"));
}

TEST_F(FileChunkStoreTest, BEH_MoveTo) {
  std::shared_ptr<FileChunkStore> fcs(
      new FileChunkStore());
  std::shared_ptr<FileChunkStore> sink_fcs(
      new FileChunkStore());

  EXPECT_FALSE(fcs->MoveTo("somechunk", sink_fcs.get()));
}

TEST_F(FileChunkStoreTest, BEH_Size) {
  std::shared_ptr<FileChunkStore> fcs(
      new FileChunkStore());
  EXPECT_EQ(0, fcs->Size("somechunk"));

  EXPECT_TRUE(fcs->Init(chunk_dir_, 5));

  EXPECT_EQ(0, fcs->Size("somechunk"));

  //  init
  EXPECT_TRUE(fcs->Init(chunk_dir_));
  EXPECT_EQ(0, fcs->Size(""));
}

TEST_F(FileChunkStoreTest, BEH_Count) {
  std::shared_ptr<FileChunkStore> fcs(
      new FileChunkStore());
  EXPECT_EQ(0, fcs->Count("somechunk"));
}

TEST_F(FileChunkStoreTest, BEH_Methods) {
  std::shared_ptr<FileChunkStore> fcs(
      new FileChunkStore());
  EXPECT_EQ(12345, fcs->GetNumFromString("12345"));
  EXPECT_EQ(0, fcs->GetNumFromString("not_a_num123"));

  EXPECT_TRUE(fcs->Init(chunk_dir_, 10));

  std::string content(RandomString(100));
  std::string chunk_name(crypto::Hash<crypto::SHA512>(content));

  fs::path chunk_path = fcs->ChunkNameToFilePath(chunk_name);
  EXPECT_FALSE(fs::exists(chunk_path));
  chunk_path.replace_extension(".1");
  EXPECT_FALSE(fs::exists(chunk_path));
  chunk_path = fcs->ChunkNameToFilePath(chunk_name, true);
  EXPECT_TRUE(fs::exists(chunk_path.parent_path()));
  EXPECT_TRUE(fcs->Store(chunk_name, content));
  EXPECT_FALSE(fs::exists(chunk_path));
  chunk_path.replace_extension(".1");
  EXPECT_TRUE(fs::exists(chunk_path));
  EXPECT_TRUE(fcs->Store(chunk_name, content));
  EXPECT_FALSE(fs::exists(chunk_path));
  chunk_path.replace_extension(".2");
  EXPECT_TRUE(fs::exists(chunk_path));

  std::string small_cc(RandomString(1));
  std::string small_cn(crypto::Hash<crypto::SHA512>(small_cc));
  fs::path small_cp = fcs->ChunkNameToFilePath(small_cn);
  EXPECT_FALSE(fs::exists(small_cp));
  small_cp.replace_extension(".1");
  EXPECT_FALSE(fs::exists(small_cp));
  small_cp  = fcs->ChunkNameToFilePath(small_cn, true);
  EXPECT_TRUE(fs::exists(small_cp.parent_path()));
  EXPECT_TRUE(fcs->Store(small_cn, small_cc));
  small_cp.replace_extension(".1");
  EXPECT_TRUE(fs::exists(small_cp));

  fcs->Clear();

  content = RandomString(50);
  chunk_name = crypto::Hash<crypto::SHA512>(content);

  EXPECT_TRUE(fcs->Init(chunk_dir_, 4));

  //  store chunks
  for (int i = 0; i < 6; ++i) {
    content = RandomString(50);
    chunk_name = crypto::Hash<crypto::SHA512>(content);

    chunk_path = fcs->ChunkNameToFilePath(chunk_name);
    chunk_path.replace_extension(".1");
    EXPECT_TRUE(fcs->Store(chunk_name, content));
    EXPECT_TRUE(fs::exists(chunk_path));
  }

  //  cause exception in RetrieveChunkInfo
  std::shared_ptr<FileChunkStore> excep_chunk_store(
      new FileChunkStore());
  fs::path ch_folder(*test_dir_ / "no_chunks");
  EXPECT_TRUE(excep_chunk_store->Init(ch_folder));
  FileChunkStore::RestoredChunkStoreInfo chunk_info =
      excep_chunk_store->RetrieveChunkInfo(fs::path("non existant"));
  EXPECT_EQ(0, chunk_info.first);
  EXPECT_EQ(0, chunk_info.second);
}

TEST_F(FileChunkStoreTest, BEH_GetChunksContinuity) {
  // store chunks in one chunk store, retrieve list with GetChunks. Create new chunk store
  // with same storage dir and retrieve chunks again through GetChunks. Result of both
  // Gets should match.

  std::vector<ChunkData> chunk_data_pre;
  std::vector<ChunkData> chunk_data_post;
  {
    std::shared_ptr<FileChunkStore> fcs_1(new FileChunkStore());

    std::vector<std::pair<std::string, std::string>> chunks;
    for (int i = 0; i < 100; ++i) {
      std::string content(RandomString(100 + (i % 20)));
      std::string name(crypto::Hash<crypto::SHA512>(content));
      chunks.push_back(std::make_pair(name, content));
    }

    EXPECT_TRUE(fcs_1->Init(chunk_dir_, 5));

    for (auto it = chunks.begin(); it != chunks.end(); ++it) {
      EXPECT_TRUE(fcs_1->Store(it->first, it->second));
      EXPECT_EQ(fcs_1->Size(it->first), it->second.size());
    }

    EXPECT_EQ(100, fcs_1->Count());

    chunk_data_pre = fcs_1->GetChunks();
    EXPECT_EQ(100, chunk_data_pre.size());
  }
  {
    std::shared_ptr<FileChunkStore> fcs_2(new FileChunkStore());
    EXPECT_EQ(0, chunk_data_post.size());
    EXPECT_TRUE(fcs_2->Init(chunk_dir_, 5));
    EXPECT_EQ(100, fcs_2->Count());

    chunk_data_post = fcs_2->GetChunks();
    EXPECT_EQ(100, chunk_data_post.size());
  }

  for (auto before = chunk_data_pre.begin(), after = chunk_data_post.begin();
       before != chunk_data_pre.end(), after != chunk_data_post.end(); ++before, ++after) {
    EXPECT_EQ(before->chunk_name, after->chunk_name);
    EXPECT_EQ(before->chunk_size, after->chunk_size);
  }
}

}  // namespace test

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
