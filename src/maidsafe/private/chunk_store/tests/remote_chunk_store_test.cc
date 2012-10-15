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
#include "boost/filesystem/fstream.hpp"
#include "boost/thread.hpp"

#include "gmock/gmock.h"

#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/asio_service.h"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/chunk_type.h"
#include "maidsafe/private/chunk_store/buffered_chunk_store.h"
#include "maidsafe/private/chunk_store/remote_chunk_store.h"
#include "maidsafe/private/chunk_store/tests/mock_chunk_manager.h"


namespace fs = boost::filesystem;
namespace args = std::placeholders;

namespace maidsafe {

namespace priv {

namespace chunk_store {

namespace test {

class RemoteChunkStoreTest: public testing::Test {
 public:
  RemoteChunkStoreTest()
      : test_dir_(maidsafe::test::CreateTestPath("MaidSafe_Test_RemoteChunkStore")),
        chunk_dir_(*test_dir_ / "chunks"),
        asio_service_(21),
        chunk_store_(),
        mock_manager_chunk_store_(),
        mock_chunk_manager_(),
        mutex_(),
        cond_var_(),
        parallel_tasks_(0),
        task_number_(0),
        num_successes_(0),
        rcs_pending_ops_conn_(),
        fob_(utils::GenerateFob(nullptr)),
        alternate_fob_(utils::GenerateFob(nullptr)),
        signed_data_(),
        store_failed_callback_(),
        store_success_callback_(),
        modify_failed_callback_(),
        modify_success_callback_(),
        delete_failed_callback_(),
        delete_success_callback_(),
        empty_callback_() {}

  void DoGet(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
             const ChunkId& chunk_name,
             const NonEmptyString& chunk_content,
             int task_num) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (task_number_ < task_num)
        cond_var_.wait(lock);
      ++task_number_;
    }
    EXPECT_TRUE(EqualChunks(chunk_content.string(), chunk_store->Get(chunk_name, fob_)));
    LOG(kInfo) << "DoGet - " << Base32Substr(chunk_name)
               << " - before lock, parallel_tasks_ = " << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    cond_var_.notify_all();
    LOG(kInfo) << "DoGet - " << Base32Substr(chunk_name)
               << " - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void DoGetAndLock(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
                    const ChunkId& chunk_name,
                    const ChunkVersion& local_version,
                    const NonEmptyString& chunk_content,
                    int task_num) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (task_number_ < task_num)
        cond_var_.wait(lock);
      ++task_number_;
    }
    std::string retrieved_content;
    chunk_store->GetAndLock(chunk_name, local_version, fob_, &retrieved_content);
    EXPECT_TRUE(EqualChunks(chunk_content.string(), retrieved_content))
                << " - before lock, parallel_tasks_ = " << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    cond_var_.notify_all();
    LOG(kInfo) << "DoGetAndLock - " << Base32Substr(chunk_name)
                << " - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void DoStore(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
               const ChunkId& chunk_name,
               const NonEmptyString& chunk_content,
               int task_num) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (task_number_ < task_num)
        cond_var_.wait(lock);
    }
    EXPECT_TRUE(chunk_store->Store(chunk_name, chunk_content, store_success_callback_, fob_));
    LOG(kInfo) << "DoStore - " << Base32Substr(chunk_name) << " - before lock, parallel_tasks_ = "
               << parallel_tasks_;
    {
      boost::mutex::scoped_lock lock(mutex_);
      --parallel_tasks_;
      ++task_number_;
      cond_var_.notify_all();
      LOG(kInfo) << "DoStore - " << Base32Substr(chunk_name)
                << " - end, parallel_tasks_ = " << parallel_tasks_;
    }
  }

  void DoDelete(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
                const ChunkId& chunk_name,
                const bool& expected_result,
                int task_num) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (task_number_ < task_num)
        cond_var_.wait(lock);
    }
    EXPECT_EQ(expected_result, chunk_store->Delete(chunk_name, delete_success_callback_, fob_));
    LOG(kInfo) << "DoDelete - " << Base32Substr(chunk_name) << " - before lock, parallel_tasks_ = "
               << parallel_tasks_;
    {
      boost::mutex::scoped_lock lock(mutex_);
      --parallel_tasks_;
      ++task_number_;
      cond_var_.notify_all();
      LOG(kInfo) << "DoDelete - " << Base32Substr(chunk_name)
                  << " - end, parallel_tasks_ = " << parallel_tasks_;
    }
  }

  void DoModify(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
                const ChunkId& chunk_name,
                const NonEmptyString& chunk_content,
                int task_num) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (task_number_ < task_num)
        cond_var_.wait(lock);
    }
    EXPECT_TRUE(chunk_store->Modify(chunk_name, chunk_content, modify_success_callback_, fob_));
    LOG(kInfo) << "DoModify - " << Base32Substr(chunk_name) << " - before lock, parallel_tasks_ = "
               << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    ++task_number_;
    cond_var_.notify_all();
    LOG(kInfo) << "DoModify - " << Base32Substr(chunk_name)
                << " - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void DoDeleteWithoutTest(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
                           const ChunkId& chunk_name) {
    if (chunk_store->Delete(chunk_name, delete_failed_callback_, fob_))
      ++num_successes_;
    LOG(kInfo) << "DoDeleteWithoutTest - " << Base32Substr(chunk_name)
               << " - before lock, parallel_tasks_ = " << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    cond_var_.notify_all();
    LOG(kInfo) << "DoDeleteWithoutTest - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void DoModifyWithoutTest(std::shared_ptr<priv::chunk_store::RemoteChunkStore> chunk_store,
                           const ChunkId& chunk_name,
                           const NonEmptyString& chunk_content,
                           int task_num) {
    {
      boost::mutex::scoped_lock lock(mutex_);
      while (task_number_ < task_num)
        cond_var_.wait(lock);
    }
    chunk_store->Modify(chunk_name, chunk_content, empty_callback_, fob_);
    LOG(kInfo) << "DoModifyWithoutTest - " << Base32Substr(chunk_name)
               << " - before lock, parallel_tasks_ = " << parallel_tasks_;
    boost::mutex::scoped_lock lock(mutex_);
    --parallel_tasks_;
    ++task_number_;
    cond_var_.notify_all();
    LOG(kInfo) << "DoModifyWithoutTest - " << Base32Substr(chunk_name)
                << " - end, parallel_tasks_ = " << parallel_tasks_;
  }

  void StoreSuccessfulCallback(bool success) {
    EXPECT_TRUE(success);
    LOG(kInfo) << "StoreSuccessfulCallback reached";
  }

  void StoreFailedCallback(bool success) {
    EXPECT_FALSE(success);
  }

  void ModifySuccessfulCallback(bool success) {
    EXPECT_TRUE(success);
  }

  void ModifyFailedCallback(bool success) {
    EXPECT_FALSE(success);
  }

  void DeleteSuccessfulCallback(bool success) {
    EXPECT_TRUE(success);
  }

  void DeleteFailedCallback(bool success) {
    EXPECT_FALSE(success);
  }

  void EmptyCallback(bool /*success*/) {}

  void PrintPendingOps(size_t num_pending_ops) {
    LOG(kInfo) << "Number of pending ops according to signal: " << num_pending_ops;
    LOG(kInfo) << "Number of pending ops according to getter: " << chunk_store_->NumPendingOps();
  }

  ~RemoteChunkStoreTest() {}

 protected:
  void SetUp() {
    asio_service_.Start();
    fs::create_directories(chunk_dir_);
    InitLocalChunkStore(&chunk_store_, chunk_dir_, asio_service_.service());
    InitMockManagerChunkStore(&mock_manager_chunk_store_, chunk_dir_, asio_service_.service());
    signed_data_.set_data(RandomString(50));
    std::string* signature = signed_data_.mutable_signature();
    *signature = asymm::Sign(asymm::PlainText(signed_data_.data()), fob_.keys.private_key).string();
    store_failed_callback_ = [=] (bool result) { StoreFailedCallback(result); };  // NOLINT (Fraser)
    store_success_callback_ = [=] (bool result) { StoreSuccessfulCallback(result); };  // NOLINT (Fraser)
    modify_failed_callback_ = [=] (bool result) { ModifyFailedCallback(result); };  // NOLINT (Fraser)
    modify_success_callback_ = [=] (bool result) { ModifySuccessfulCallback(result); };  // NOLINT (Fraser)
    delete_failed_callback_ = [=] (bool result) { DeleteFailedCallback(result); };  // NOLINT (Fraser)
    delete_success_callback_ = [=] (bool result) { DeleteSuccessfulCallback(result); };  // NOLINT (Fraser)
    empty_callback_ = [=] (bool result) { EmptyCallback(result); };  // NOLINT (Fraser)
    rcs_pending_ops_conn_ = this->chunk_store_->sig_num_pending_ops()->connect(
            boost::bind(&RemoteChunkStoreTest::PrintPendingOps, this, _1));
  }

  void TearDown() {
    rcs_pending_ops_conn_.disconnect();
    asio_service_.Stop();
  }

  std::shared_ptr<RemoteChunkStore> CreateMockManagerChunkStore(
      const fs::path& base_dir,
      boost::asio::io_service& asio_service) {
    std::shared_ptr<BufferedChunkStore> buffered_chunk_store(new BufferedChunkStore(asio_service));
    std::string buffered_chunk_store_dir("buffered_chunk_store" + RandomAlphaNumericString(8));
    buffered_chunk_store->Init(base_dir / buffered_chunk_store_dir);
    std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority(
        new chunk_actions::ChunkActionAuthority(buffered_chunk_store));
    mock_chunk_manager_.reset(new MockChunkManager(buffered_chunk_store));

    return std::shared_ptr<RemoteChunkStore>(new RemoteChunkStore(buffered_chunk_store,
                                                                  mock_chunk_manager_,
                                                                  chunk_action_authority));
  }

  void InitLocalChunkStore(std::shared_ptr<RemoteChunkStore>* chunk_store,
                           const fs::path& chunk_dir,
                           boost::asio::io_service&  asio_service) {
    chunk_store->reset();
    fs::path chunk_lock_path = *test_dir_ / "chunk_locks";
    fs::path buffered_chunk_store_path(chunk_dir / RandomAlphaNumericString(8));
    fs::path local_repository(chunk_dir / "local_repository");
    *chunk_store = CreateLocalChunkStore(buffered_chunk_store_path,
                                         local_repository,
                                         chunk_lock_path,
                                         asio_service);
    (*chunk_store)->SetCompletionWaitTimeout(std::chrono::seconds(3));
    (*chunk_store)->SetOperationWaitTimeout(std::chrono::seconds(2));
  }

  void InitMockManagerChunkStore(std::shared_ptr<RemoteChunkStore>* chunk_store,
                                 const fs::path& chunk_dir,
                                 boost::asio::io_service& asio_service) {
    chunk_store->reset();
    *chunk_store = CreateMockManagerChunkStore(chunk_dir, asio_service);
    (*chunk_store)->SetCompletionWaitTimeout(std::chrono::seconds(3));
    (*chunk_store)->SetOperationWaitTimeout(std::chrono::seconds(2));
  }

  void GenerateChunk(ChunkType chunk_type,
                     const size_t& chunk_size,
                     const asymm::PrivateKey& private_key,
                     ChunkId* chunk_name,
                     NonEmptyString* chunk_contents) {
    switch (chunk_type) {
      case ChunkType::kDefault:
        *chunk_contents = NonEmptyString(RandomString(chunk_size));
        *chunk_name = crypto::Hash<crypto::SHA512>(*chunk_contents);
        break;
      case ChunkType::kModifiableByOwner:
        {
          priv::chunk_actions::SignedData chunk;
          chunk.set_data(RandomString(chunk_size));
          std::string* signature = chunk.mutable_signature();
          *signature = asymm::Sign(asymm::PlainText(chunk.data()), private_key).string();
          *chunk_name = ApplyTypeToName(NodeId(RandomString(64)), ChunkType::kModifiableByOwner);
          *chunk_contents = NonEmptyString(chunk.SerializeAsString());
        }
        break;
      case ChunkType::kUnknown:
        {
          priv::chunk_actions::SignedData chunk;
          chunk.set_data(RandomString(chunk_size));
          std::string* signature = chunk.mutable_signature();
          *signature = asymm::Sign(asymm::PlainText(chunk.data()), private_key).string();
          *chunk_name = ApplyTypeToName(NodeId(RandomString(64)), ChunkType::kUnknown);
          *chunk_contents = NonEmptyString(chunk.SerializeAsString());
        break;
        }
      default:
        LOG(kError) << "GenerateChunk - Unsupported type " << static_cast<int>(chunk_type);
    }
  }

  testing::AssertionResult EqualChunks(const std::string& chunk1, const std::string& chunk2) {
    if (chunk1 == chunk2)
      return testing::AssertionSuccess();
    else
      return testing::AssertionFailure() << "'" << Base32Substr(chunk1) << "' vs. '"
                                         << Base32Substr(chunk2) << "'";
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
  int task_number_;
  int num_successes_;

  bs2::connection rcs_pending_ops_conn_;

  Fob fob_;
  Fob alternate_fob_;
  priv::chunk_actions::SignedData signed_data_;
  std::function<void(bool)> store_failed_callback_;  // NOLINT (Philip)
  std::function<void(bool)> store_success_callback_;  // NOLINT (Philip)
  std::function<void(bool)> modify_failed_callback_;  // NOLINT (Philip)
  std::function<void(bool)> modify_success_callback_;  // NOLINT (Philip)
  std::function<void(bool)> delete_failed_callback_;  // NOLINT (Philip)
  std::function<void(bool)> delete_success_callback_;  // NOLINT (Philip)
  std::function<void(bool)> empty_callback_;  // NOLINT (Philip)
};

TEST_F(RemoteChunkStoreTest, BEH_Get) {
  NonEmptyString content(RandomString(100));
  ChunkId name(crypto::Hash<crypto::SHA512>(content));

  // invalid chunks, should fail
  EXPECT_THROW(this->chunk_store_->Get(ChunkId(), fob_), std::exception);
  EXPECT_TRUE(this->chunk_store_->Get(name, fob_).empty());
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  // existing chunk
  EXPECT_EQ(content.string(), this->chunk_store_->Get(name, fob_));
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, BEH_GetAndLock) {
  NonEmptyString content(RandomString(100));
  ChunkId name(crypto::Hash<crypto::SHA512>(content));
  std::string retrieved_content;
  // invalid chunks, should fail
  EXPECT_THROW(this->chunk_store_->GetAndLock(ChunkId(), ChunkVersion(), fob_, &retrieved_content),
               std::exception);
  EXPECT_TRUE(retrieved_content.empty());
  EXPECT_EQ(kGeneralError,
            this->chunk_store_->GetAndLock(name, ChunkVersion(), fob_, &retrieved_content));
  EXPECT_TRUE(retrieved_content.empty());
  EXPECT_EQ(kGeneralError, this->chunk_store_->GetAndLock(name, ChunkVersion(), fob_, nullptr));
  EXPECT_TRUE(retrieved_content.empty());
  EXPECT_EQ(kGeneralError, this->chunk_store_->GetAndLock(name, ChunkVersion(), Fob(),
                                                          &retrieved_content));
  EXPECT_TRUE(retrieved_content.empty());

  // existing chunk
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  EXPECT_EQ(kSuccess,
            this->chunk_store_->GetAndLock(name, ChunkVersion(), fob_, &retrieved_content));
  EXPECT_EQ(content.string(), retrieved_content);

  // existing MBO chunk
  GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &name, &content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  EXPECT_EQ(kSuccess,
            this->chunk_store_->GetAndLock(name, ChunkVersion(), fob_, &retrieved_content));
  EXPECT_EQ(content.string(), retrieved_content);

  // chunk that exists locally with same version as requested
  GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &name, &content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  ChunkVersion up_to_date_local_version(crypto::Hash<crypto::Tiger>(content));
  EXPECT_EQ(kChunkNotModified, this->chunk_store_->GetAndLock(name, up_to_date_local_version, fob_,
                                                              &retrieved_content));
  EXPECT_TRUE(retrieved_content.empty());
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, BEH_Store) {
  NonEmptyString content(RandomString(123));
  ChunkId name(crypto::Hash<crypto::SHA512>(content));
  // invalid input
  EXPECT_THROW(this->chunk_store_->Store(name, NonEmptyString(""), store_failed_callback_, fob_),
               std::exception);
  EXPECT_THROW(this->chunk_store_->Store(ChunkId(), content, store_failed_callback_, fob_),
               std::exception);

  EXPECT_TRUE(this->chunk_store_->Empty());
  // EXPECT_EQ(0, this->chunk_store_->Count());
  EXPECT_EQ(0U, this->chunk_store_->Size());
  // EXPECT_FALSE(this->chunk_store_->Has(name));
  // EXPECT_EQ(0, this->chunk_store_->Count(name));
  // EXPECT_EQ(0, this->chunk_store_->Size(name));

//  valid store
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  // EXPECT_FALSE(this->chunk_store_->Empty());
  // EXPECT_EQ(123, this->chunk_store_->Size());
  // EXPECT_EQ(1, this->chunk_store_->Count());
  // EXPECT_TRUE(this->chunk_store_->Has(name));
  // EXPECT_EQ(1, this->chunk_store_->Count(name));
  // EXPECT_EQ(123, this->chunk_store_->Size(name));
  ASSERT_EQ(name.string(),
            crypto::Hash<crypto::SHA512>(this->chunk_store_->Get(name, fob_)).string());
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, BEH_Delete) {
  NonEmptyString content;
  ChunkId name;
  // TODO(Philip): Reinstate this test when RemoteChunkStore has been fully
  // updated
  /*GenerateChunk(priv::chunk_actions::ChunkType::kUnknown,
                   123, fob_.keys.private_key, &name, &content);
  // Deleting chunk of unknown type should fail
  ASSERT_FALSE(this->chunk_store_->Delete(name, delete_failed_callback_,
                                          fob_));*/
  GenerateChunk(ChunkType::kDefault, 123, fob_.keys.private_key, &name, &content);
  EXPECT_TRUE(this->chunk_store_->Get(name, fob_).empty());
  EXPECT_TRUE(this->chunk_store_->Empty());
  // EXPECT_FALSE(this->chunk_store_->Has(name));
  // EXPECT_EQ(0, this->chunk_store_->Count(name));
  // EXPECT_EQ(0, this->chunk_store_->Size(name));
  EXPECT_EQ(0U, this->chunk_store_->Size());

  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  EXPECT_FALSE(this->chunk_store_->Empty());
  // EXPECT_TRUE(this->chunk_store_->Has(name));
  // EXPECT_EQ(1, this->chunk_store_->Count(name));
  // EXPECT_EQ(123, this->chunk_store_->Size(name));
  EXPECT_EQ(content.string(), this->chunk_store_->Get(name, fob_));
  ASSERT_TRUE(this->chunk_store_->Delete(name, delete_success_callback_, fob_));
  EXPECT_TRUE(this->chunk_store_->Get(name, fob_).empty());
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, BEH_Modify) {
  NonEmptyString content, new_content;
  ChunkId name, dummy;

  // test that modifying of chunk of default type fails
  {
    GenerateChunk(ChunkType::kDefault, 123, fob_.keys.private_key, &name, &content);
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &dummy, &new_content);

    ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
    ASSERT_TRUE(chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));
    EXPECT_EQ(content.string(), this->chunk_store_->Get(name, fob_));

    ASSERT_FALSE(this->chunk_store_->Modify(name, new_content, modify_failed_callback_, fob_));
    EXPECT_EQ(content.string(), this->chunk_store_->Get(name, fob_));
  }

  // test modifying of chunk of modifiable by owner type
  {
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &name, &content);
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &dummy, &new_content);

    ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
    ASSERT_TRUE(chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));
    EXPECT_EQ(content.string(), this->chunk_store_->Get(name, fob_));

    // modify without correct validation data should fail
    this->chunk_store_->Modify(name, new_content, modify_failed_callback_, alternate_fob_);
    EXPECT_EQ(content.string(), this->chunk_store_->Get(name, fob_));

    // modify with correct validation data should succeed
    ASSERT_TRUE(this->chunk_store_->Modify(name, new_content, modify_success_callback_, fob_));
    EXPECT_EQ(new_content.string(), this->chunk_store_->Get(name, fob_));
  }
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, FUNC_ConcurrentGets) {
//  FLAGS_ms_logging_private = google::INFO;
  size_t kNumChunks(5);
  int kNumConcurrentGets(5);
  std::map<ChunkId, std::pair<NonEmptyString, NonEmptyString>> chunks;
  ChunkId dummy;

  while (chunks.size() < kNumChunks) {
    NonEmptyString chunk_content, chunk_new_content;
    ChunkId chunk_name;
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &chunk_name,
                  &chunk_content);
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &dummy,
                  &chunk_new_content);
    chunks[chunk_name].first = chunk_content;
    chunks[chunk_name].second = chunk_new_content;
  }

  boost::thread_group thread_group;
  for (auto it = chunks.begin(); it != chunks.end(); ++it)
    ASSERT_TRUE(chunk_store_->Store(it->first, it->second.first, store_success_callback_, fob_));
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    for (int i(0); i < kNumConcurrentGets; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      thread_group.create_thread([=] {
          DoGet(chunk_store_, it->first, it->second.first, 0);
      });
    }
  }
  {
    this->chunk_store_->WaitForCompletion();
  }
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    ASSERT_TRUE(chunk_store_->Modify(it->first, it->second.second, store_success_callback_, fob_));
  }
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    for (int i(0); i < kNumConcurrentGets; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      thread_group.create_thread([=] {
          DoGet(chunk_store_, it->first, it->second.second, 0);
      });
    }
  }
  {
    chunk_store_->WaitForCompletion();
    boost::mutex::scoped_lock lock(mutex_);
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                      [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  this->chunk_store_->LogStats();
}

// TODO(Fraser#5#): 2012-10-08 - This test is flawed and should only be re-enabled (and refactored)
//                  if the test is run against a VaultChunkManager rather than a LocalChunkManager.
TEST_F(RemoteChunkStoreTest, DISABLED_FUNC_ConcurrentGetAndLocks) {
  size_t kNumChunks(5);
  int kNumConcurrentGets(5);
  std::map<ChunkId, std::pair<NonEmptyString, NonEmptyString>> chunks;
  ChunkId dummy;

  while (chunks.size() < kNumChunks) {
    NonEmptyString chunk_content, chunk_new_content;
    ChunkId chunk_name;
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &chunk_name,
                  &chunk_content);
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &dummy,
                  &chunk_new_content);
    chunks[chunk_name].first = chunk_content;
    chunks[chunk_name].second = chunk_new_content;
  }
  boost::thread_group thread_group_;
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    ASSERT_TRUE(chunk_store_->Store(it->first, it->second.first, store_success_callback_, fob_));
  }
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    for (int i(0); i < kNumConcurrentGets; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      thread_group_.create_thread([=] {
          DoGetAndLock(chunk_store_, it->first, ChunkVersion(), it->second.first, 0);
      });
    }
  }
  {
    chunk_store_->WaitForCompletion();
    boost::mutex::scoped_lock lock(mutex_);
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                     [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    ASSERT_TRUE(chunk_store_->Modify(it->first, it->second.second,
                                     store_success_callback_, fob_));
  }
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    for (int i(0); i < kNumConcurrentGets; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      thread_group_.create_thread([=] {
          DoGetAndLock(chunk_store_, it->first, ChunkVersion(), it->second.second, 0);
      });
    }
  }
  {
    chunk_store_->WaitForCompletion();
    boost::mutex::scoped_lock lock(mutex_);
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                     [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  this->chunk_store_->LogStats();
}

// TODO(Fraser#5#): 2012-10-08 - This test is flawed and should only be re-enabled (and refactored)
//                  if the test is run against a VaultChunkManager rather than a LocalChunkManager.
TEST_F(RemoteChunkStoreTest, DISABLED_FUNC_MixedConcurrentGets) {
  size_t kNumChunks(5);
  int kNumConcurrentGets(2);
  std::map<ChunkId, std::pair<NonEmptyString, NonEmptyString>> chunks;
  ChunkId dummy;

  while (chunks.size() < kNumChunks) {
    NonEmptyString chunk_content, chunk_new_content;
    ChunkId chunk_name;
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &chunk_name,
                  &chunk_content);
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &dummy,
                  &chunk_new_content);
    chunks[chunk_name].first = chunk_content;
    chunks[chunk_name].second = chunk_new_content;
  }
  boost::thread_group thread_group;
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    ASSERT_TRUE(chunk_store_->Store(it->first, it->second.first, store_success_callback_, fob_));
  }
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    for (int i(0); i < kNumConcurrentGets; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      thread_group.create_thread([=] {
        DoGetAndLock(chunk_store_, it->first, ChunkVersion(), it->second.first, 0);
      });
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      thread_group.create_thread([=] { DoGet(chunk_store_, it->first, it->second.first, 0); });  // NOLINT (Fraser)
    }
  }
  {
    chunk_store_->WaitForCompletion();
    boost::mutex::scoped_lock lock(mutex_);
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                     [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    ASSERT_TRUE(chunk_store_->Modify(it->first, it->second.second, store_success_callback_, fob_));
  }
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    for (int i(0); i < kNumConcurrentGets; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      thread_group.create_thread([=] {
          DoGetAndLock(chunk_store_, it->first, ChunkVersion(), it->second.second, 0);
      });
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      thread_group.create_thread([=] { DoGet(chunk_store_, it->first, it->second.second, 0); });  // NOLINT (Fraser)
    }
  }
  {
    chunk_store_->WaitForCompletion();
    boost::mutex::scoped_lock lock(mutex_);
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                      [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, FUNC_ConflictingDeletes) {
  NonEmptyString content, new_content;
  ChunkId name, dummy;
  task_number_ = 0;
  GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &name, &content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < 10; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      asio_service_.service().post(std::bind(&RemoteChunkStoreTest::DoDelete, this, chunk_store_,
                                             name, true, task_number_));
    }
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                      [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, FUNC_ConflictingDeletesAndModifies) {
  NonEmptyString content, new_content;
  ChunkId name, dummy;
  task_number_ = 0;
  int task_number_initialiser(0);
  GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &name, &content);
  GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &dummy, &new_content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < 10; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      asio_service_.service().post(std::bind(&RemoteChunkStoreTest::DoModifyWithoutTest, this,
                                             chunk_store_, name, new_content, 0));
      ++task_number_initialiser;
    }
    for (int i(0); i < 10; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      asio_service_.service().post(std::bind(&RemoteChunkStoreTest::DoDelete, this, chunk_store_,
                                             name, true, 0));
      ++task_number_initialiser;
    }
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                      [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, FUNC_RedundantModifies) {
  int kNumModifies(10);
  NonEmptyString content, new_content;
  ChunkId name, dummy;
  GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &name, &content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  EXPECT_EQ(content.string(), this->chunk_store_->Get(name, fob_));

  std::vector<NonEmptyString> new_content_vector;
  for (int i(0); i < kNumModifies; ++i) {
    GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &dummy, &new_content);
    new_content_vector.push_back(new_content);
  }
  // test sequential modifies
  for (int i(0); i < kNumModifies; ++i) {
    EXPECT_TRUE(chunk_store_->Modify(name, new_content_vector.at(i), modify_success_callback_,
                                     fob_));
    EXPECT_EQ(new_content_vector.at(i).string(), this->chunk_store_->Get(name, fob_));
  }
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  EXPECT_EQ((*(new_content_vector.rbegin())).string(), this->chunk_store_->Get(name, fob_));

  // test concurrent modifies
  GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &name, &content);
  ASSERT_TRUE(this->chunk_store_->Store(name, content, store_success_callback_, fob_));
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  EXPECT_EQ(content.string(), this->chunk_store_->Get(name, fob_));
  // int task_num_initialiser(0);
  // task_number_ = 0;
  {
    boost::mutex::scoped_lock lock(mutex_);
    for (int i(0); i < kNumModifies; ++i) {
      ++parallel_tasks_;
      LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
      asio_service_.service().post(std::bind(&RemoteChunkStoreTest::DoModify, this, chunk_store_,
                                             name, new_content_vector.at(i), 0));
      // ++task_num_initialiser;
    }
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                      [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }
  ASSERT_TRUE(chunk_store_->WaitForCompletion());
  Sleep(boost::posix_time::seconds(1));
  // EXPECT_EQ(**(new_content_vector.rbegin()), this->chunk_store_->Get(name, fob_));
  this->chunk_store_->LogStats();
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
    std::map<ChunkId, NonEmptyString> chunks;
    parallel_tasks_ = 0;
    while (chunks.size() < kNumChunks) {
      NonEmptyString chunk_content;
      ChunkId chunk_name;
      GenerateChunk(ChunkType::kDefault, 123, fob_.keys.private_key, &chunk_name, &chunk_content);
      chunks[chunk_name] = chunk_content;
    }
    task_number_ = 0;
    int task_number_initialiser(0);
    for (auto it = chunks.begin(); it != chunks.end(); ++it) {
      ++parallel_tasks_;
      asio_service_.service().post(std::bind(&RemoteChunkStoreTest::DoStore, this,
                                             this->chunk_store_, it->first, it->second,
                                             task_number_initialiser));
      ++task_number_initialiser;
    }
    for (auto it = chunks.begin(); it != chunks.end(); ++it) {
      ++parallel_tasks_;
      asio_service_.service().post(std::bind(&RemoteChunkStoreTest::DoGet, this, this->chunk_store_,
                                             it->first, it->second, task_number_initialiser));
      ++task_number_initialiser;
    }
    for (auto it = chunks.begin(); it != chunks.end(); ++it) {
      ++parallel_tasks_;
      asio_service_.service().post(std::bind(&RemoteChunkStoreTest::DoDelete, this,
                                             this->chunk_store_, it->first, true,
                                             task_number_initialiser));
      ++task_number_initialiser;
    }
    boost::mutex::scoped_lock lock(mutex_);
    ASSERT_TRUE(cond_var_.timed_wait(lock, boost::posix_time::seconds(10),
                                      [&] { return parallel_tasks_ <= 0; }));  // NOLINT (Philip)
  }

  ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, FUNC_Order) {
  const size_t kNumChunks(static_cast<size_t>(20));
  const size_t kRepeatTimes(7);

  std::map<ChunkId, NonEmptyString> chunks;
  while (chunks.size() < kNumChunks) {
    ChunkId chunk_name;
    NonEmptyString chunk_contents;
    if (chunks.size() < kNumChunks / 2)
      GenerateChunk(ChunkType::kDefault, 123, asymm::PrivateKey(), &chunk_name, &chunk_contents);
    else
      GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &chunk_name,
                    &chunk_contents);
    chunks[chunk_name] = chunk_contents;
  }

  // check ops are executed in order
  for (auto it = chunks.begin(); it != chunks.end(); ++it) {
    EXPECT_TRUE(this->chunk_store_->Delete(it->first, delete_success_callback_, fob_));
    EXPECT_TRUE(this->chunk_store_->Store(it->first, it->second, store_success_callback_, fob_));
    EXPECT_TRUE(this->chunk_store_->Delete(it->first, delete_success_callback_, fob_));
    EXPECT_TRUE(this->chunk_store_->Store(it->first, it->second, store_success_callback_, fob_));

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());

    ASSERT_TRUE(EqualChunks(it->second.string(), this->chunk_store_->Get(it->first, fob_)));

    EXPECT_TRUE(this->chunk_store_->Delete(it->first, delete_success_callback_, fob_));
    EXPECT_TRUE(this->chunk_store_->Get(it->first, fob_).empty());

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
  }

  // Repeatedly store a chunk, then repeatedly delete it
  {
    NonEmptyString chunk_content(RandomString(123));
    ChunkId chunk_name(crypto::Hash<crypto::SHA512>(chunk_content));
    for (size_t i(0); i < kRepeatTimes; ++i)
      EXPECT_TRUE(this->chunk_store_->Store(chunk_name, chunk_content, store_success_callback_,
                                            fob_));

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));

    EXPECT_TRUE(EqualChunks(chunk_content.string(), this->chunk_store_->Get(chunk_name, fob_)));

    for (size_t i(0); i < kRepeatTimes - 1; ++i)
      EXPECT_TRUE(this->chunk_store_->Delete(chunk_name, delete_success_callback_, fob_));

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));

    EXPECT_TRUE(EqualChunks(chunk_content.string(), this->chunk_store_->Get(chunk_name, fob_)));

    EXPECT_TRUE(this->chunk_store_->Delete(chunk_name, delete_success_callback_, fob_));

    ASSERT_TRUE(this->chunk_store_->WaitForCompletion());
    Sleep(boost::posix_time::seconds(1));

    this->chunk_store_->Clear();
    EXPECT_TRUE(this->chunk_store_->Get(chunk_name, fob_).empty());
  }
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, FUNC_GetTimeout) {
  NonEmptyString content(RandomString(100));
  ChunkId name(crypto::Hash<crypto::SHA512>(content));
  EXPECT_CALL(*mock_chunk_manager_, GetChunk(testing::_, testing::_, testing::_, testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(&MockChunkManager::Timeout,
                                                                 mock_chunk_manager_.get()))));
  for (int i(0); i < 10; ++i) {
    ++parallel_tasks_;
    std::string content;
    LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
    asio_service_.service().post(std::bind(&RemoteChunkStore::Get, mock_manager_chunk_store_, name,
                                           fob_));
    asio_service_.service().post(std::bind(&RemoteChunkStore::GetAndLock, mock_manager_chunk_store_,
                                           name, ChunkVersion(), fob_, &content));
  }
  Sleep(boost::posix_time::seconds(1));
  this->mock_manager_chunk_store_->WaitForCompletion();
  this->chunk_store_->LogStats();
}

TEST_F(RemoteChunkStoreTest, FUNC_ConflictingDeletesTimeout) {
  NonEmptyString content;
  ChunkId name;
  num_successes_ = 0;
  GenerateChunk(ChunkType::kModifiableByOwner, 123, fob_.keys.private_key, &name, &content);
  EXPECT_CALL(*mock_chunk_manager_, StoreChunk(testing::_, testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(&MockChunkManager::StoreChunkPass,
                                                                 mock_chunk_manager_.get(),
                                                                 name))));
  EXPECT_TRUE(this->mock_manager_chunk_store_->Store(name, content, store_success_callback_,
                                                     fob_));
  Sleep(boost::posix_time::seconds(1));
  mock_manager_chunk_store_->WaitForCompletion();
  EXPECT_CALL(*mock_chunk_manager_, DeleteChunk(testing::_, testing::_))
      .WillOnce(testing::WithArgs<0>(testing::Invoke(boost::bind(&MockChunkManager::Timeout,
                                                                 mock_chunk_manager_.get()))));
  for (int i(0); i < 5; ++i) {
    ++parallel_tasks_;
    LOG(kInfo) << "Before Posting: Parallel tasks: " << parallel_tasks_;
    asio_service_.service().post(std::bind(&RemoteChunkStoreTest::DoDeleteWithoutTest, this,
                                           mock_manager_chunk_store_, name));
  }
  Sleep(boost::posix_time::seconds(1));
  mock_manager_chunk_store_->WaitForCompletion();
  ASSERT_EQ(1, num_successes_);
  this->chunk_store_->LogStats();
}

}  // namespace test

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
