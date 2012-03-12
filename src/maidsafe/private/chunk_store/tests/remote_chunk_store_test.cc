/* Copyright (c) 2011 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <memory>

#include "boost/filesystem.hpp"
#include "boost/filesystem/fstream.hpp"
#include "boost/thread.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/asio_service.h"

#include "maidsafe/private/chunk_store/remote_chunk_store.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace chunk_store {

namespace test {

class RemoteChunkStoreTest: public testing::Test {
 public:
  RemoteChunkStoreTest()
      : test_dir_(maidsafe::test::CreateTestPath("MaidSafe_TestRChunkStore")),
        chunk_dir_(*test_dir_ / "chunks"),
        alt_chunk_dir_(*test_dir_ / "chunks_alt"),
        tiger_chunk_dir_(*test_dir_ / "chunks_tiger"),
        asio_service_(),
        chunk_store_(),
        alt_chunk_store_(),
        tiger_chunk_store_(),
        mutex_(),
        cond_var_(),
        parallel_tasks_(0) {}

  void DoGet(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
             const std::string &chunk_name,
             const std::string &chunk_content) {
    EXPECT_TRUE(EqualChunks(chunk_content, chunk_store->Get(chunk_name)));
    DLOG(INFO) << "DoGet - before lock, parallel_tasks_ = " << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    cond_var_.notify_all();
    DLOG(INFO) << "DoGet - end, parallel_tasks_ = " << parallel_tasks_;
  }

  ~RemoteChunkStoreTest() {}

 protected:
  void SetUp() {
    asio_service_.Start(3);
    fs::create_directories(chunk_dir_);
    fs::create_directories(alt_chunk_dir_);
    fs::create_directories(tiger_chunk_dir_);
    InitChunkStore(&chunk_store_, chunk_dir_, asio_service_.service());
    InitChunkStore(&alt_chunk_store_, alt_chunk_dir_, asio_service_.service());
    InitChunkStore(&tiger_chunk_store_,
                   tiger_chunk_dir_,
                   asio_service_.service());
  }

  void TearDown() {
    asio_service_.Stop();
  }

  void InitChunkStore(std::shared_ptr<RemoteChunkStore> *chunk_store,
                      const fs::path &chunk_dir,
                      boost::asio::io_service &asio_service) {
  chunk_store->reset();
  *chunk_store = CreateLocalChunkStore(chunk_dir, asio_service);
}

  fs::path CreateRandomFile(const fs::path &file_path,
                            const uint64_t &file_size) {
    fs::ofstream ofs(file_path, std::ios::binary | std::ios::out |
                                std::ios::trunc);
    if (file_size != 0) {
      size_t string_size = (file_size > 100000) ? 100000 :
                          static_cast<size_t>(file_size);
      uint64_t remaining_size = file_size;
      std::string rand_str = RandomString(2 * string_size);
      std::string file_content;
      uint64_t start_pos = 0;
      while (remaining_size) {
        srand(17);
        start_pos = rand() % string_size;  // NOLINT (Fraser)
        if (remaining_size < string_size) {
          string_size = static_cast<size_t>(remaining_size);
          file_content = rand_str.substr(0, string_size);
        } else {
          file_content = rand_str.substr(static_cast<size_t>(start_pos),
                                        string_size);
        }
        ofs.write(file_content.c_str(), file_content.size());
        remaining_size -= string_size;
      }
    }
    ofs.close();
    return file_path;
  }
   testing::AssertionResult EqualChunks(const std::string &chunk1,
                                       const std::string &chunk2) {
    if (chunk1 == chunk2)
      return testing::AssertionSuccess();
    else
      return testing::AssertionFailure() << "'" << Base32Substr(chunk1)
                                         << "' vs. '" << Base32Substr(chunk2)
                                         << "'";
  }

  maidsafe::test::TestPath test_dir_;
  fs::path chunk_dir_, alt_chunk_dir_, tiger_chunk_dir_;
  AsioService asio_service_;
  std::shared_ptr<RemoteChunkStore> chunk_store_,
                              alt_chunk_store_,
                              tiger_chunk_store_;

  boost::mutex mutex_;
  boost::condition_variable cond_var_;

  size_t parallel_tasks_;
};

TEST_F(RemoteChunkStoreTest, BEH_Get) {
  std::string content(RandomString(100));
  std::string name(crypto::Hash<crypto::SHA512>(content));
  fs::path path(*this->test_dir_ / "chunk.dat");
  ASSERT_FALSE(fs::exists(path));

  // non-existant chunk, should fail
  EXPECT_TRUE(this->chunk_store_->Get("").empty());
  EXPECT_TRUE(this->chunk_store_->Get(name).empty());
  EXPECT_FALSE(this->chunk_store_->Get(name, path));
  EXPECT_FALSE(fs::exists(path));

  ASSERT_TRUE(this->chunk_store_->Store(name, content));
  // existing chunk
  EXPECT_EQ(content, this->chunk_store_->Get(name));
  EXPECT_TRUE(this->chunk_store_->Get(name, path));
  EXPECT_TRUE(fs::exists(path));
  EXPECT_EQ(name, crypto::HashFile<crypto::SHA512>(path));

  EXPECT_FALSE(this->chunk_store_->Empty());
  // existing output file, should overwrite
  this->CreateRandomFile(path, 99);
  EXPECT_NE(name, crypto::HashFile<crypto::SHA512>(path));
  EXPECT_TRUE(this->chunk_store_->Get(name, path));
  EXPECT_EQ(name, crypto::HashFile<crypto::SHA512>(path));
  // invalid file name
  EXPECT_FALSE(this->chunk_store_->Get(name, fs::path("")));
}



TEST_F(RemoteChunkStoreTest, BEH_Store) {
  std::string content(RandomString(123));
  std::string name_mem(crypto::Hash<crypto::SHA512>(content));
  fs::path path(*this->test_dir_ / "chunk.dat");
  this->CreateRandomFile(path, 456);
  fs::path path_empty(*this->test_dir_ / "empty.dat");
  this->CreateRandomFile(path_empty, 0);
  std::string name_file(crypto::HashFile<crypto::SHA512>(path));
  ASSERT_NE(name_mem, name_file);

  // invalid input
  EXPECT_FALSE(this->chunk_store_->Store(name_mem, ""));
  EXPECT_FALSE(this->chunk_store_->Store("", content));
  EXPECT_FALSE(this->chunk_store_->Store(name_file, "", false));
  EXPECT_FALSE(this->chunk_store_->Store(name_file, *this->test_dir_ / "fail",
                                         false));
  EXPECT_FALSE(this->chunk_store_->Store("", path, false));
  EXPECT_FALSE(this->chunk_store_->Store(name_file, path_empty, false));
  EXPECT_TRUE(this->chunk_store_->Empty());
  EXPECT_EQ(0, this->chunk_store_->Count());
  EXPECT_EQ(0, this->chunk_store_->Size());
  EXPECT_FALSE(this->chunk_store_->Has(name_mem));
  EXPECT_EQ(0, this->chunk_store_->Count(name_mem));
  EXPECT_EQ(0, this->chunk_store_->Size(name_mem));
  EXPECT_FALSE(this->chunk_store_->Has(name_file));
  EXPECT_EQ(0, this->chunk_store_->Count(name_file));
  EXPECT_EQ(0, this->chunk_store_->Size(name_file));

  // store from string
  ASSERT_TRUE(this->chunk_store_->Store(name_mem, content));
  EXPECT_FALSE(this->chunk_store_->Empty());
  /*EXPECT_EQ(1, this->chunk_store_->Count());
  EXPECT_EQ(123, this->chunk_store_->Size());*/
  EXPECT_TRUE(this->chunk_store_->Has(name_mem));
  /*EXPECT_EQ(1, this->chunk_store_->Count(name_mem));
  EXPECT_EQ(123, this->chunk_store_->Size(name_mem));*/
  EXPECT_FALSE(this->chunk_store_->Has(name_file));
  EXPECT_EQ(0, this->chunk_store_->Count(name_file));
  EXPECT_EQ(0, this->chunk_store_->Size(name_file));

  ASSERT_EQ(name_mem,
            crypto::Hash<crypto::SHA512>(this->chunk_store_->Get(name_mem)));

  // store from file
  ASSERT_TRUE(this->chunk_store_->Store(name_file, path, false));
  EXPECT_FALSE(this->chunk_store_->Empty());
  /*EXPECT_EQ(2, this->chunk_store_->Count());
  EXPECT_EQ(579, this->chunk_store_->Size());*/
  EXPECT_TRUE(this->chunk_store_->Has(name_mem));
  /*EXPECT_EQ(1, this->chunk_store_->Count(name_mem));
  EXPECT_EQ(123, this->chunk_store_->Size(name_mem));*/
  EXPECT_TRUE(this->chunk_store_->Has(name_file));
  /*EXPECT_EQ(1, this->chunk_store_->Count(name_file));
  EXPECT_EQ(456, this->chunk_store_->Size(name_file));*/

  ASSERT_EQ(name_file,
            crypto::Hash<crypto::SHA512>(this->chunk_store_->Get(name_file)));

  fs::path new_path(*this->test_dir_ / "chunk2.dat");
  this->CreateRandomFile(new_path, 333);
  std::string new_name(crypto::HashFile<crypto::SHA512>(new_path));
}

TEST_F(RemoteChunkStoreTest, BEH_ConcurrentGets) {
  std::string content(RandomString(123));
  std::string name_mem(crypto::Hash<crypto::SHA512>(content));
  std::string new_content(RandomString(123));
  ASSERT_TRUE(this->chunk_store_->Store(name_mem, content));
  EXPECT_FALSE(this->chunk_store_->Empty());
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < 10; ++i) {
      ++parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoGet, this, chunk_store_, name_mem,
          content));
    }
    BOOST_VERIFY(cond_var_.timed_wait(
                      lock, boost::posix_time::seconds(10),
                      [&]()->bool {
                          return parallel_tasks_ > 0; }));  // NOLINT (Philip)
  }

  ASSERT_TRUE(this->chunk_store_->Modify(name_mem, new_content));
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < 10; ++i) {
      ++parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoGet, this, chunk_store_, name_mem,
          new_content));
    }
    BOOST_VERIFY(cond_var_.timed_wait(
                        lock, boost::posix_time::seconds(10),
                        [&]()->bool {
                            return parallel_tasks_ > 0; }));  // NOLINT (Philip)
  }
}


}  // namespace test

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
