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

#include "gmock/gmock.h"

#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/asio_service.h"

#include "maidsafe/private/chunk_actions/chunk_types.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"
#include "maidsafe/private/chunk_store/tests/mock_chunk_manager.h"

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
        asio_service_(),
        chunk_store_(),
        mock_manager_chunk_store_(),
        mock_chunk_manager_(),
        mutex_(),
        cond_var_(),
        parallel_tasks_(0),
        keys_(),
        data_(),
        signed_data_(),
        failed_callback_(),
        success_callback_() {}

  void DoGet(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
             const std::string &chunk_name,
             const std::string &chunk_content) {
    EXPECT_TRUE(EqualChunks(chunk_content,
                            chunk_store->Get(chunk_name, data_)));
    DLOG(ERROR) << "DoGet - before lock, parallel_tasks_ = " << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    cond_var_.notify_all();
    DLOG(ERROR) << "DoGet - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void DoStore(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
               const std::string &chunk_name,
               const std::string &chunk_content) {
    EXPECT_TRUE(chunk_store->Store(chunk_name, chunk_content,
                                   success_callback_, data_));
    DLOG(INFO) << "DoStore - before lock, parallel_tasks_ = "
               << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    cond_var_.notify_all();
    DLOG(INFO) << "DoStore - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void DoModify(
             std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
             const std::string &chunk_name,
             const std::string &chunk_content) {
    EXPECT_TRUE(chunk_store->Modify(chunk_name, chunk_content,
                                         success_callback_, data_));
    DLOG(ERROR) << "DoModify - before lock, parallel_tasks_ = "
                << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    cond_var_.notify_all();
    DLOG(ERROR) << "DoModify - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void DoDelete(
      std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
      const std::string &chunk_name,
      const bool &expected_result) {
    EXPECT_EQ(expected_result, chunk_store->Delete(chunk_name,
                                                   success_callback_, data_));
    DLOG(INFO) << "DoDelete - before lock, parallel_tasks_ = "
               << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    cond_var_.notify_all();
    DLOG(INFO) << "DoDelete - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void SuccessfulCallback(bool success) {
    EXPECT_TRUE(success);
  }

  void FailedCallback(bool success) {
    EXPECT_FALSE(success);
  }

  ~RemoteChunkStoreTest() {}

 protected:
  void SetUp() {
    asio_service_.Start(10);
    fs::create_directories(chunk_dir_);
    InitLocalChunkStore(&chunk_store_, chunk_dir_, asio_service_.service());
    InitMockManagerChunkStore(&mock_manager_chunk_store_,
                              chunk_dir_,
                              asio_service_.service());
    maidsafe::rsa::GenerateKeyPair(&keys_);
    signed_data_.set_data(RandomString(50));
    asymm::Sign(signed_data_.data(), keys_.private_key,
            signed_data_.mutable_signature());
    data_ = priv::chunk_store::RemoteChunkStore::ValidationData(keys_,
                signed_data_.SerializeAsString());
    failed_callback_ = std::bind(&RemoteChunkStoreTest::FailedCallback,
                                 this, args::_1);
    success_callback_ = std::bind(&RemoteChunkStoreTest::SuccessfulCallback,
                                  this, args::_1);
  }

  void TearDown() {
    asio_service_.Stop();
  }

  std::shared_ptr<RemoteChunkStore> CreateMockManagerChunkStore(
      const fs::path &base_dir,
      boost::asio::io_service &asio_service) {
    std::shared_ptr<BufferedChunkStore> buffered_chunk_store(
        new BufferedChunkStore(asio_service));
    std::string buffered_chunk_store_dir("buffered_chunk_store" +
                                       RandomAlphaNumericString(8));
    buffered_chunk_store->Init(base_dir / buffered_chunk_store_dir);
    std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority(
        new chunk_actions::ChunkActionAuthority(buffered_chunk_store));
    mock_chunk_manager_ =
        std::make_shared<MockChunkManager>(buffered_chunk_store);

    return std::make_shared<RemoteChunkStore>(buffered_chunk_store,
                                            mock_chunk_manager_,
                                            chunk_action_authority);
  }

  void InitLocalChunkStore(std::shared_ptr<RemoteChunkStore> *chunk_store,
                      const fs::path &chunk_dir,
                      boost::asio::io_service &asio_service) {
    chunk_store->reset();
    *chunk_store = CreateLocalChunkStore(chunk_dir, asio_service);
  }
  void InitMockManagerChunkStore(std::shared_ptr<RemoteChunkStore> *chunk_store,
                      const fs::path &chunk_dir,
                      boost::asio::io_service &asio_service) {
    chunk_store->reset();
    *chunk_store = CreateMockManagerChunkStore(chunk_dir, asio_service);
  }

  void GenerateChunk(unsigned char chunk_type,
                     const size_t &chunk_size,
                     const asymm::PrivateKey &private_key,
                     std::string *chunk_name,
                     std::string *chunk_contents) {
    switch (chunk_type) {
      case priv::chunk_actions::kDefaultType:
        *chunk_contents = RandomString(chunk_size);
        *chunk_name = crypto::Hash<crypto::SHA512>(*chunk_contents);
        break;
      case priv::chunk_actions::kModifiableByOwner:
        {
          priv::chunk_actions::SignedData chunk;
          chunk.set_data(RandomString(chunk_size));
          asymm::Sign(chunk.data(), private_key, chunk.mutable_signature());
          *chunk_name = priv::chunk_actions::ApplyTypeToName(
              RandomString(64), priv::chunk_actions::kModifiableByOwner);
          chunk.SerializeToString(chunk_contents);
        }
        break;
      case priv::chunk_actions::kUnknownType:
        {
          priv::chunk_actions::SignedData chunk;
          chunk.set_data(RandomString(chunk_size));
          asymm::Sign(chunk.data(), private_key, chunk.mutable_signature());
          *chunk_name = priv::chunk_actions::ApplyTypeToName(
              RandomString(64), priv::chunk_actions::kUnknownType);
          chunk.SerializeToString(chunk_contents);
        }
      default:
        LOG(ERROR) << "GenerateChunk - Unsupported type "
                   << static_cast<int>(chunk_type);
    }
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
  fs::path chunk_dir_;
  AsioService asio_service_;
  std::shared_ptr<RemoteChunkStore> chunk_store_;
  std::shared_ptr<RemoteChunkStore> mock_manager_chunk_store_;
  std::shared_ptr<MockChunkManager> mock_chunk_manager_;

  boost::mutex mutex_;
  boost::condition_variable cond_var_;

  size_t parallel_tasks_;

  maidsafe::rsa::Keys keys_;
  priv::chunk_store::RemoteChunkStore::ValidationData data_;
  priv::chunk_actions::SignedData signed_data_;
  std::function<void(bool)> failed_callback_;  // NOLINT (Philip)
  std::function<void(bool)> success_callback_;  // NOLINT (Philip)
};

TEST_F(RemoteChunkStoreTest, BEH_Get) {
  std::string content(RandomString(100));
  std::string name(crypto::Hash<crypto::SHA512>(content));

  // invalid chunks, should fail
  EXPECT_TRUE(this->chunk_store_->Get("").empty());
  EXPECT_TRUE(this->chunk_store_->Get(name).empty());
  ASSERT_TRUE(this->chunk_store_->Store(name, content, success_callback_));
  // existing chunk
  EXPECT_EQ(content, this->chunk_store_->Get(name));
}



TEST_F(RemoteChunkStoreTest, BEH_Store) {
  std::string content(RandomString(123));
  std::string name(crypto::Hash<crypto::SHA512>(content));
  // invalid input
  EXPECT_FALSE(this->chunk_store_->Store(name, "", failed_callback_));
  EXPECT_FALSE(this->chunk_store_->Store("", content, failed_callback_));

  EXPECT_TRUE(this->chunk_store_->Empty());
  // EXPECT_EQ(0, this->chunk_store_->Count());
  EXPECT_EQ(0, this->chunk_store_->Size());
  // EXPECT_FALSE(this->chunk_store_->Has(name));
  // EXPECT_EQ(0, this->chunk_store_->Count(name));
  // EXPECT_EQ(0, this->chunk_store_->Size(name));

//  valid store
  ASSERT_TRUE(this->chunk_store_->Store(name, content, success_callback_));
  // EXPECT_FALSE(this->chunk_store_->Empty());
  // EXPECT_EQ(123, this->chunk_store_->Size());
  // EXPECT_EQ(1, this->chunk_store_->Count());
  // EXPECT_TRUE(this->chunk_store_->Has(name));
  // EXPECT_EQ(1, this->chunk_store_->Count(name));
  // EXPECT_EQ(123, this->chunk_store_->Size(name));
  ASSERT_EQ(name,
            crypto::Hash<crypto::SHA512>(this->chunk_store_->Get(name)));
}

TEST_F(RemoteChunkStoreTest, BEH_Delete) {
  std::string content;
  std::string name;

  GenerateChunk(priv::chunk_actions::kUnknownType, 123,
                keys_.private_key, &name, &content);
  // Deleting chunk of unknown type should fail
  ASSERT_FALSE(this->chunk_store_->Delete(name, failed_callback_));

  GenerateChunk(priv::chunk_actions::kDefaultType, 123,
                keys_.private_key, &name, &content);
  EXPECT_TRUE(this->chunk_store_->Get(name).empty());
  EXPECT_TRUE(this->chunk_store_->Empty());

  // EXPECT_FALSE(this->chunk_store_->Has(name));
  // EXPECT_EQ(0, this->chunk_store_->Count(name));
  // EXPECT_EQ(0, this->chunk_store_->Size(name));
  EXPECT_EQ(0, this->chunk_store_->Size());

  ASSERT_TRUE(this->chunk_store_->Store(name, content, success_callback_));
  EXPECT_FALSE(this->chunk_store_->Empty());
  // EXPECT_TRUE(this->chunk_store_->Has(name));
  // EXPECT_EQ(1, this->chunk_store_->Count(name));
  // EXPECT_EQ(123, this->chunk_store_->Size(name));
  EXPECT_EQ(content, this->chunk_store_->Get(name));
  ASSERT_TRUE(this->chunk_store_->Delete(name, success_callback_));
  EXPECT_TRUE(this->chunk_store_->Get(name).empty());
}

TEST_F(RemoteChunkStoreTest, BEH_Modify) {
  std::string content, name, new_content, dummy;

  // test that modifying of chunk of default type fails
  {
    GenerateChunk(priv::chunk_actions::kDefaultType, 123,
                  keys_.private_key, &name, &content);
    GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                    keys_.private_key, &dummy, &new_content);

    ASSERT_TRUE(this->chunk_store_->Store(name, content,
                                          success_callback_, data_));
    ASSERT_TRUE(chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));
    EXPECT_EQ(content, this->chunk_store_->Get(name));

    ASSERT_FALSE(this->chunk_store_->Modify(name, new_content,
                                           failed_callback_, data_));
    EXPECT_EQ(content, this->chunk_store_->Get(name));
  }

  // test modifying of chunk of modifiable by owner type
  {
    GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                  keys_.private_key, &name, &content);
    GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                    keys_.private_key, &dummy, &new_content);

    ASSERT_TRUE(this->chunk_store_->Store(name, content,
                                          success_callback_, data_));
    ASSERT_TRUE(chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));
    EXPECT_EQ(content, this->chunk_store_->Get(name));

    // modify without correct validation data should fail
    this->chunk_store_->Modify(name, new_content, failed_callback_);
    EXPECT_EQ(content, this->chunk_store_->Get(name));

    // modify with correct validation data should succeed
    ASSERT_TRUE(this->chunk_store_->Modify(name, new_content,
                                           success_callback_, data_));
    EXPECT_EQ(new_content, this->chunk_store_->Get(name));
  }
}

TEST_F(RemoteChunkStoreTest, FUNC_ConcurrentGets) {
  std::string content, name, new_content, dummy;
  GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                keys_.private_key, &name, &content);
  GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                keys_.private_key, &dummy, &new_content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content,
                                        success_callback_, data_));
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  // EXPECT_FALSE(this->chunk_store_->Empty());
  // EXPECT_EQ(123, this->chunk_store_->Size());
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < 10; ++i) {
      ++parallel_tasks_;
      DLOG(INFO) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoGet, this, chunk_store_, name,
          content));
    }
    BOOST_VERIFY(cond_var_.timed_wait(
                        lock, boost::posix_time::seconds(60),
                        [&]()->bool {
                            return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  ASSERT_TRUE(this->chunk_store_->Modify(name, new_content,
                                         success_callback_, data_));
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < 10; ++i) {
      ++parallel_tasks_;
      DLOG(INFO) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoGet, this, chunk_store_, name,
          new_content));
    }
    BOOST_VERIFY(cond_var_.timed_wait(
                        lock, boost::posix_time::seconds(10),
                        [&]()->bool {
                            return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
}

TEST_F(RemoteChunkStoreTest, FUNC_ConflictingDeletes) {
  std::string content, name, new_content, dummy;
  GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                keys_.private_key, &name, &content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content,
                                        success_callback_, data_));
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < 5; ++i) {
      ++parallel_tasks_;
      DLOG(INFO) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoDelete, this, chunk_store_, name,
          true));
    }
    BOOST_VERIFY(cond_var_.timed_wait(
                        lock, boost::posix_time::seconds(60),
                        [&]()->bool {
                            return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
}

TEST_F(RemoteChunkStoreTest, FUNC_RedundantModifies) {
  int kNumModifies(10);
  std::string content, name, new_content, dummy;
  GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                keys_.private_key, &name, &content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content,
                                        success_callback_, data_));
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  EXPECT_EQ(content, this->chunk_store_->Get(name));

  std::vector<std::string*> new_content_vector;
  for (int i(0); i < kNumModifies; ++i) {
    std::string* new_content = new std::string;
    GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                keys_.private_key, &dummy, new_content);
    new_content_vector.push_back(new_content);
  }
  // test sequential modifies
  for (int i(0); i < kNumModifies; ++i) {
    EXPECT_TRUE(chunk_store_->Modify(name, *(new_content_vector.at(i)),
                                     success_callback_, data_));
    EXPECT_EQ(*(new_content_vector.at(i)), this->chunk_store_->Get(name));
  }
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  EXPECT_EQ(**(new_content_vector.rbegin()), this->chunk_store_->Get(name));

  // test concurrent modifies
  GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                keys_.private_key, &name, &content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content,
                                        success_callback_, data_));
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  EXPECT_EQ(content, this->chunk_store_->Get(name));
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < kNumModifies; ++i) {
      ++parallel_tasks_;
      DLOG(INFO) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoModify, this, chunk_store_, name,
          *(new_content_vector.at(i))));
    }
    BOOST_VERIFY(cond_var_.timed_wait(
                        lock, boost::posix_time::seconds(10),
                        [&]()->bool {
                            return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  // EXPECT_EQ(**(new_content_vector.rbegin()), this->chunk_store_->Get(name));
}

TEST_F(RemoteChunkStoreTest, FUNC_MultiThreads) {
  const size_t kNumChunks(static_cast<size_t>(5));
  {
    // Store kNumChunks of chunks
    // and
    // Get kNumChunks of chunks
    // and
    // Delete kNumChunks of chunks
    // at the same time
    std::map<std::string, std::string> chunks;
    while (chunks.size() < kNumChunks) {
      std::string chunk_content(RandomString(123));
      std::string chunk_name(crypto::Hash<crypto::SHA512>(chunk_content));
      chunks[chunk_name] = chunk_content;
    }

    boost::mutex::scoped_lock lock(mutex_);
    for (auto it = chunks.begin(); it != chunks.end(); ++it) {
      ++parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoStore, this, this->chunk_store_, it->first,
          it->second));
    }
    for (auto it = chunks.begin(); it != chunks.end(); ++it) {
      ++parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoGet, this, this->chunk_store_, it->first,
          it->second));
    }
    for (auto it = chunks.begin(); it != chunks.end(); ++it) {
      ++parallel_tasks_;
      asio_service_.service().post(std::bind(
          &RemoteChunkStoreTest::DoDelete, this, this->chunk_store_, it->first,
          true));
    }
    BOOST_VERIFY(cond_var_.timed_wait(lock, boost::posix_time::seconds(60),
                    [&]()->bool { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }

  ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
}

TEST_F(RemoteChunkStoreTest, FUNC_Order) {
  const size_t kNumChunks(static_cast<size_t>(20));
  const size_t kRepeatTimes(7);

  std::map<std::string, std::string> chunks;
  while (chunks.size() < kNumChunks) {
    std::string chunk_name, chunk_contents;
    if (chunks.size() < kNumChunks / 2)
      GenerateChunk(priv::chunk_actions::kDefaultType, 123,
                    asymm::PrivateKey(), &chunk_name, &chunk_contents);
    else
      GenerateChunk(priv::chunk_actions::kModifiableByOwner, 123,
                    keys_.private_key, &chunk_name,
                    &chunk_contents);
    chunks[chunk_name] = chunk_contents;
  }

  // check ops are executed in order
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    EXPECT_TRUE(this->chunk_store_->Delete(it->first, success_callback_,
                                           data_));
    EXPECT_TRUE(this->chunk_store_->Store(it->first, it->second,
                                          success_callback_, data_));
    EXPECT_TRUE(this->chunk_store_->Delete(it->first, success_callback_,
                                           data_));
    EXPECT_TRUE(this->chunk_store_->Store(it->first, it->second,
                                          success_callback_, data_));

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));

    ASSERT_TRUE(EqualChunks(it->second, this->chunk_store_->Get(it->first,
                                                                data_)));

    EXPECT_TRUE(this->chunk_store_->Delete(it->first,
                                           success_callback_,
                                           data_));
    EXPECT_TRUE(this->chunk_store_->Get(it->first, data_).empty());

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));
  }

  // Repeatedly store a chunk, then repeatedly delete it
  {
    std::string chunk_content(RandomString(123));
    std::string chunk_name(crypto::Hash<crypto::SHA512>(chunk_content));
    for (size_t i(0); i < kRepeatTimes; ++i)
      EXPECT_TRUE(this->chunk_store_->Store(
          chunk_name, chunk_content, success_callback_, data_));

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));

    EXPECT_TRUE(EqualChunks(chunk_content,
                            this->chunk_store_->Get(chunk_name, data_)));

    for (size_t i(0); i < kRepeatTimes - 1; ++i)
      EXPECT_TRUE(this->chunk_store_->Delete(
          chunk_name, success_callback_, data_));

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));

    EXPECT_TRUE(EqualChunks(chunk_content,
                            this->chunk_store_->Get(chunk_name, data_)));

    EXPECT_TRUE(this->chunk_store_->Delete(
        chunk_name, success_callback_, data_));

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));

    this->chunk_store_->Clear();
    EXPECT_TRUE(this->chunk_store_->Get(chunk_name, data_).empty());
  }
}

TEST_F(RemoteChunkStoreTest, BEH_GetTimeout) {
  std::string content(RandomString(100));
  std::string name(crypto::Hash<crypto::SHA512>(content));
  for (int i(0); i < 3; ++i) {
    ++parallel_tasks_;
    DLOG(INFO) << "Before Posting: Parallel tasks: " << parallel_tasks_;
    asio_service_.service().post(std::bind(
      &RemoteChunkStore::Get, mock_manager_chunk_store_, name, data_));
  }
  EXPECT_CALL(*mock_chunk_manager_, GetChunk(testing::_,
                                        testing::_,
                                        testing::_,
                                        testing::_))
      .WillRepeatedly(testing::WithArgs<0>(testing::Invoke(std::bind(
          &MockChunkManager::GetChunkTimeout, mock_chunk_manager_.get()))));
  Sleep(boost::posix_time::seconds(1));
  ASSERT_FALSE(this->mock_manager_chunk_store_->WaitForCompletion());
}

}  // namespace test

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
