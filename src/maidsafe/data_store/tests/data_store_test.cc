/*******************************************************************************
 *  Copyright 2012 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ******************************************************************************/

#include "maidsafe/data_store/data_store.h"
#include "maidsafe/data_store/data_buffer.h"

#include <memory>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"


namespace fs = boost::filesystem;
namespace args = std::placeholders;

namespace maidsafe {

namespace data_store {

namespace test {

typedef std::pair<uint64_t, uint64_t> MaxMemoryDiskUsage;
const uint64_t OneKB(1024);
const uint64_t kDefaultMaxMemoryUsage(1000);
const uint64_t kDefaultMaxDiskUsage(2000);

template <typename StoragePolicy>
class DataStoreTest : public ::testing::Test {
 protected:
  // typedef StoragePolicy StoragePolicy;
  typedef typename DataStore<StoragePolicy>::PopFunctor PopFunctor;

  DataStoreTest()
    : max_memory_usage_(kDefaultMaxMemoryUsage),
      max_disk_usage_(kDefaultMaxDiskUsage),
      data_buffer_path_(),
      pop_functor_(),
      data_store_(new DataStore<StoragePolicy>(max_memory_usage_, max_disk_usage_, pop_functor_))
  {}
  
  void SetUp() {}

  template<typename KeyType>
  void PopFunction(const KeyType& key_popped,
                   const NonEmptyString& value_popped,
                   const std::vector<std::pair<KeyType, NonEmptyString> >& key_value_pairs,
                   size_t& cur_popped_index,
                   std::mutex& pop_mutex,
                   std::condition_variable& pop_cond_var) {
    {
      std::unique_lock<std::mutex> lock(pop_mutex);
      KeyType to_be_popped_key(key_value_pairs[cur_popped_index].first);
      NonEmptyString to_be_popped_value(key_value_pairs[cur_popped_index].second);
      EXPECT_EQ(to_be_popped_key.data, key_popped.data);
      EXPECT_EQ(to_be_popped_value, value_popped);
      ++cur_popped_index;
    }
    pop_cond_var.notify_one();
  }

  bool DeleteDirectory(const fs::path& directory) {
    boost::system::error_code error_code;
    fs::directory_iterator end;
    try {
    fs::directory_iterator it(directory);
    for (; it != end; ++it)
      fs::remove_all((*it).path(), error_code);
      if (error_code)
        return false;
    }
    catch(const std::exception &e) {
      LOG(kError) << e.what();
      return false;
    }
    return true;
  }

  template<typename KeyType>
  std::vector<std::pair<KeyType, NonEmptyString>> PopulateDataStore(
      size_t num_entries,
      size_t num_memory_entries,
      size_t num_disk_entries,
      maidsafe::test::TestPath test_path,
      const PopFunctor& pop_functor) {
    boost::system::error_code error_code;
    data_buffer_path_ = fs::path(*test_path / "data_buffer");
    std::vector<std::pair<KeyType, NonEmptyString>> key_value_pairs;
    NonEmptyString value, recovered;
    KeyType key;

    EXPECT_TRUE(fs::create_directories(data_buffer_path_, error_code)) << data_buffer_path_ << ": "
                                                                       << error_code.message();
    EXPECT_EQ(0, error_code.value()) << data_buffer_path_ << ": " << error_code.message();
    EXPECT_TRUE(fs::exists(data_buffer_path_, error_code)) << data_buffer_path_ << ": "
                                                           << error_code.message();
    EXPECT_EQ(0, error_code.value());

    for (size_t i = 0; i < num_entries; ++i) {
      value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(OneKB))));
      key.data = Identity(crypto::Hash<crypto::SHA512>(value));
      key_value_pairs.push_back(std::make_pair(key, value));
    }
    data_store_.reset(new DataStore<StoragePolicy>(MemoryUsage(num_memory_entries * OneKB),
                                                   DiskUsage(num_disk_entries * OneKB),
                                                   pop_functor, data_buffer_path_));
    for (auto key_value : key_value_pairs) {
      EXPECT_NO_THROW(data_store_->Store(key_value.first, key_value.second));
      EXPECT_NO_THROW(recovered = data_store_->Get(key_value.first));
      EXPECT_EQ(key_value.second, recovered);
    }
    return key_value_pairs;
  }

  boost::filesystem::path GetkDiskBuffer(const DataStore<StoragePolicy>& data_store) {
    return data_store.kDiskBuffer_;
  }

  MemoryUsage max_memory_usage_;
  DiskUsage max_disk_usage_;
  fs::path data_buffer_path_;
  PopFunctor pop_functor_;
  std::unique_ptr<DataStore<StoragePolicy>> data_store_;
};

//typedef std::pair<uint64_t, uint64_t> MaxMemoryDiskUsage;
//const uint64_t OneKB(1024);
//const uint64_t kDefaultMaxMemoryUsage(1000);
//const uint64_t kDefaultMaxDiskUsage(2000);
//
//class DataBufferTest : public testing::Test {
// protected:
//  DataBufferTest()
//      : max_memory_usage_(kDefaultMaxMemoryUsage),
//        max_disk_usage_(kDefaultMaxDiskUsage),
//        kv_buffer_path_(),
//        pop_functor_(),
//        data_buffer_(new DataBuffer(max_memory_usage_, max_disk_usage_, pop_functor_)) {}
//
//  void PopFunction(const Identity& key_popped,
//                   const NonEmptyString& value_popped,
//                   const std::vector<std::pair<Identity, NonEmptyString> >& key_value_pairs,
//                   size_t& cur_popped_index,
//                   std::mutex& pop_mutex,
//                   std::condition_variable& pop_cond_var) {
//    {
//      std::unique_lock<std::mutex> lock(pop_mutex);
//      Identity to_be_popped_key(key_value_pairs[cur_popped_index].first);
//      NonEmptyString to_be_popped_value(key_value_pairs[cur_popped_index].second);
//      EXPECT_EQ(to_be_popped_key, key_popped);
//      EXPECT_EQ(to_be_popped_value, value_popped);
//      ++cur_popped_index;
//    }
//    pop_cond_var.notify_one();
//  }
//
//  bool DeleteDirectory(const fs::path& directory) {
//    boost::system::error_code error_code;
//    fs::directory_iterator end;
//    try {
//    fs::directory_iterator it(directory);
//    for (; it != end; ++it)
//      fs::remove_all((*it).path(), error_code);
//      if (error_code)
//        return false;
//    }
//    catch(const std::exception &e) {
//      LOG(kError) << e.what();
//      return false;
//    }
//    return true;
//  }
//
//  std::vector<std::pair<Identity, NonEmptyString>> PopulateKVB(
//      size_t num_entries,
//      size_t num_memory_entries,
//      size_t num_disk_entries,
//      maidsafe::test::TestPath test_path,
//      const DataBuffer::PopFunctor& pop_functor) {
//    boost::system::error_code error_code;
//    kv_buffer_path_ = fs::path(*test_path / "kv_buffer");
//    std::vector<std::pair<Identity, NonEmptyString>> key_value_pairs;
//    NonEmptyString value, recovered;
//    Identity key;
//
//    EXPECT_TRUE(fs::create_directories(kv_buffer_path_, error_code)) << kv_buffer_path_ << ": "
//                                                                     << error_code.message();
//    EXPECT_EQ(0, error_code.value()) << kv_buffer_path_ << ": " << error_code.message();
//    EXPECT_TRUE(fs::exists(kv_buffer_path_, error_code)) << kv_buffer_path_ << ": "
//                                                         << error_code.message();
//    EXPECT_EQ(0, error_code.value());
//
//    for (size_t i = 0; i < num_entries; ++i) {
//      value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(OneKB))));
//      key = Identity(crypto::Hash<crypto::SHA512>(value));
//      key_value_pairs.push_back(std::make_pair(key, value));
//    }
//    data_buffer_.reset(new DataBuffer(MemoryUsage(num_memory_entries * OneKB),
//                                               DiskUsage(num_disk_entries * OneKB),
//                                               pop_functor, kv_buffer_path_));
//    for (auto key_value : key_value_pairs) {
//      EXPECT_NO_THROW(data_buffer_->Store(key_value.first, key_value.second));
//      EXPECT_NO_THROW(recovered = data_buffer_->Get(key_value.first));
//      EXPECT_EQ(key_value.second, recovered);
//    }
//    return key_value_pairs;
//  }
//
//  boost::filesystem::path GetkDiskBuffer(const DataBuffer& kvb) {
//    return kvb.kDiskBuffer_;
//  }
//
//  MemoryUsage max_memory_usage_;
//  DiskUsage max_disk_usage_;
//  fs::path kv_buffer_path_;
//  DataBuffer::PopFunctor pop_functor_;
//  std::unique_ptr<DataBuffer> data_buffer_;
//};

TYPED_TEST_CASE_P(DataStoreTest);

TYPED_TEST_P(DataStoreTest, BEH_Constructor) {
  EXPECT_NO_THROW(DataStore<TypeParam>(MemoryUsage(0), DiskUsage(0), pop_functor_));
  EXPECT_NO_THROW(DataStore<TypeParam>(MemoryUsage(1), DiskUsage(1), pop_functor_));
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(1), DiskUsage(0), pop_functor_),
               std::exception);
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(2), DiskUsage(1), pop_functor_),
               std::exception);
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(200001), DiskUsage(200000), pop_functor_),
               std::exception);
  EXPECT_NO_THROW(DataStore<TypeParam>(MemoryUsage(199999), DiskUsage(200000), pop_functor_));
  // Create a path to a file, and check that this can't be used as the disk buffer path.
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  ASSERT_FALSE(test_path->empty());
  boost::filesystem::path file_path(*test_path / "File");
  ASSERT_TRUE(WriteFile(file_path, " "));
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(199999),
                                    DiskUsage(200000),
                                    pop_functor_,
                                    file_path),
               std::exception);
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(199999),
                                    DiskUsage(200000),
                                    pop_functor_,
                                    file_path / "base"),
               std::exception);

  boost::filesystem::path dir_path(*test_path / "Dir");
  EXPECT_NO_THROW(DataStore<TypeParam>(MemoryUsage(1), DiskUsage(1), pop_functor_, dir_path));
  ASSERT_TRUE(fs::exists(dir_path));

  boost::filesystem::path data_store_path;
  {
    DataStore<TypeParam> data_store(MemoryUsage(1), DiskUsage(1), pop_functor_);
    data_store_path = GetkDiskBuffer(data_store);
    ASSERT_TRUE(fs::exists(data_store_path));
  }
  ASSERT_FALSE(fs::exists(data_store_path));
}

TYPED_TEST_P(DataStoreTest, BEH_SetMaxDiskMemoryUsage) {
  EXPECT_NO_THROW(data_store_->SetMaxMemoryUsage(MemoryUsage(max_disk_usage_ - 1)));
  EXPECT_NO_THROW(data_store_->SetMaxMemoryUsage(MemoryUsage(max_disk_usage_)));
  EXPECT_THROW(data_store_->SetMaxMemoryUsage(MemoryUsage(max_disk_usage_ + 1)), std::exception);
  EXPECT_THROW(data_store_->SetMaxDiskUsage(DiskUsage(max_disk_usage_ - 1)), std::exception);
  EXPECT_NO_THROW(data_store_->SetMaxDiskUsage(DiskUsage(max_disk_usage_)));
  EXPECT_NO_THROW(data_store_->SetMaxDiskUsage(DiskUsage(max_disk_usage_ + 1)));
  EXPECT_THROW(data_store_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(-1))),
               std::exception);
  EXPECT_NO_THROW(data_store_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(1))));
  EXPECT_THROW(data_store_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(0))), std::exception);
  EXPECT_NO_THROW(data_store_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(1))));
  EXPECT_NO_THROW(data_store_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(0))));
  EXPECT_NO_THROW(data_store_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(0))));
  EXPECT_NO_THROW(data_store_->SetMaxDiskUsage(DiskUsage(std::numeric_limits<uint64_t>().max())));
  EXPECT_NO_THROW(data_store_->SetMaxMemoryUsage(
    MemoryUsage(std::numeric_limits<uint64_t>().max())));
  EXPECT_THROW(data_store_->SetMaxDiskUsage(DiskUsage(kDefaultMaxDiskUsage)), std::exception);
  EXPECT_NO_THROW(data_store_->SetMaxMemoryUsage(MemoryUsage(kDefaultMaxMemoryUsage)));
  EXPECT_NO_THROW(data_store_->SetMaxDiskUsage(DiskUsage(kDefaultMaxDiskUsage)));
}

TYPED_TEST_P(DataStoreTest, BEH_RemoveDiskBuffer) {
  typedef TaggedValue<Identity, passport::detail::AnmpidTag> KeyType;
  boost::system::error_code error_code;
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  fs::path data_buffer_path(*test_path / "kv_buffer");
  const uintmax_t kMemorySize(1), kDiskSize(2);
  data_store_.reset(new DataStore<TypeParam>(MemoryUsage(kMemorySize),
                                             DiskUsage(kDiskSize),
                                             pop_functor_,
                                             data_buffer_path));
  KeyType key;
  key.data = Identity(RandomAlphaNumericString(crypto::SHA512::DIGESTSIZE));
  NonEmptyString small_value(std::string(kMemorySize, 'a'));
  EXPECT_NO_THROW(data_store_->Store(key, small_value));
  EXPECT_NO_THROW(data_store_->Delete(key));
  ASSERT_EQ(1, fs::remove_all(data_buffer_path, error_code));
  ASSERT_FALSE(fs::exists(data_buffer_path, error_code));
  // Fits into memory buffer successfully.  Background thread in future should throw, causing other
  // API functions to throw on next execution.
  EXPECT_NO_THROW(data_store_->Store(key, small_value));
  Sleep(boost::posix_time::seconds(1));
  EXPECT_THROW(data_store_->Store(key, small_value), std::exception);
  EXPECT_THROW(data_store_->Get(key), std::exception);
  EXPECT_THROW(data_store_->Delete(key), std::exception);

  data_store_.reset(new DataStore<TypeParam>(MemoryUsage(kMemorySize),
                                             DiskUsage(kDiskSize),
                                             pop_functor_,
                                             data_buffer_path));
  NonEmptyString large_value(std::string(kDiskSize, 'a'));
  EXPECT_NO_THROW(data_store_->Store(key, large_value));
  EXPECT_NO_THROW(data_store_->Delete(key));
  ASSERT_EQ(1, fs::remove_all(data_buffer_path, error_code));
  ASSERT_FALSE(fs::exists(data_buffer_path, error_code));
  // Skips memory buffer and goes straight to disk, causing exception.  Background thread in future
  // should finish, causing other API functions to throw on next execution.
  // - ADAPT TEST FOR MEMORY STORAGE ONLY!!!
  EXPECT_THROW(data_store_->Store(key, large_value), std::exception);
  EXPECT_THROW(data_store_->Get(key), std::exception);
  EXPECT_THROW(data_store_->Delete(key), std::exception);
}

TYPED_TEST_P(DataStoreTest, BEH_SuccessfulStore) {
  NonEmptyString value1(std::string(RandomAlphaNumericString(
                    static_cast<uint32_t>(max_memory_usage_))));
  TaggedValue<Identity, passport::detail::MidTag> key1(crypto::Hash<crypto::SHA512>(value1));
  NonEmptyString value2(std::string(RandomAlphaNumericString(
                    static_cast<uint32_t>(max_memory_usage_))));
  TaggedValue<Identity, passport::detail::AnmidTag> key2(crypto::Hash<crypto::SHA512>(value2));
  EXPECT_NO_THROW(data_store_->Store(key1, value1));
  EXPECT_NO_THROW(data_store_->Store(key2, value2));
  NonEmptyString recovered;
  EXPECT_NO_THROW(recovered = data_store_->Get(key1));
  EXPECT_EQ(recovered, value1);
  EXPECT_NO_THROW(recovered = data_store_->Get(key2));
  EXPECT_EQ(recovered, value2);
}

TYPED_TEST_P(DataStoreTest, BEH_UnsuccessfulStore) {
  NonEmptyString value(std::string(static_cast<uint32_t>(max_disk_usage_ + 1), 'a'));
  TaggedValue<Identity, passport::detail::SmidTag> key(crypto::Hash<crypto::SHA512>(value));
  EXPECT_THROW(data_store_->Store(key, value), std::exception);
}

TYPED_TEST_P(DataStoreTest, BEH_DeleteOnDiskBufferOverfill) {
  typedef TaggedValue<Identity, passport::detail::SmidTag> KeyType;
  const size_t num_entries(4), num_memory_entries(1), num_disk_entries(4);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  std::vector<std::pair<KeyType, NonEmptyString>> key_value_pairs(
      PopulateDataStore<KeyType>(num_entries,
                                 num_memory_entries,
                                 num_disk_entries,
                                 test_path,
                                 pop_functor_));
  NonEmptyString value, recovered;
  KeyType key;

  KeyType first_key(key_value_pairs[0].first), second_key(key_value_pairs[1].first);
  value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(2 * OneKB))));
  key.data = Identity(crypto::Hash<crypto::SHA512>(value));
  auto async = std::async(std::launch::async, [this, key, value] {
                                                  data_store_->Store(key, value);
                                              });
  EXPECT_THROW(recovered = data_store_->Get(key), std::exception);
  EXPECT_NO_THROW(data_store_->Delete(first_key));
  EXPECT_NO_THROW(data_store_->Delete(second_key));
  EXPECT_NO_THROW(async.wait());
  EXPECT_NO_THROW(recovered = data_store_->Get(key));
  EXPECT_EQ(recovered, value);

  EXPECT_TRUE(DeleteDirectory(data_buffer_path_));
}

//TYPED_TEST_P(DataStoreTest, BEH_PopOnDiskBufferOverfill) {
//  typedef TaggedValue<Identity, passport::detail::MpidTag> StoreKeyType;
//  typedef DataStore<TypeParam>::KeyType KeyType;
//  size_t cur_idx(0);
//  std::mutex pop_mutex;
//  std::condition_variable pop_cond_var;
//  std::vector<std::pair<KeyType, NonEmptyString>> key_value_pairs;
//  PopFunctor pop_functor([this, &key_value_pairs, &cur_idx, &pop_mutex,
//                    &pop_cond_var](const KeyType& key_popped, const NonEmptyString& value_popped) {
//        this->PopFunction<KeyType>(key_popped,
//                                   value_popped,
//                                   key_value_pairs,
//                                   cur_idx,
//                                   pop_mutex,
//                                   pop_cond_var);
//      });
//  const size_t num_entries(4), num_memory_entries(1), num_disk_entries(4);
//  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
//  key_value_pairs = PopulateDataStore<KeyType>(num_entries,
//                                               num_memory_entries,
//                                               num_disk_entries,
//                                               test_path,
//                                               pop_functor);
//  EXPECT_EQ(0, cur_idx);
//
//  NonEmptyString value, recovered;
//  KeyType key;
//  value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(OneKB))));
//  key.data = Identity(crypto::Hash<crypto::SHA512>(value));
//  // Trigger pop...
//  EXPECT_NO_THROW(data_store_->Store(key, value));
//  EXPECT_NO_THROW(recovered = data_store_->Get(key));
//  EXPECT_EQ(recovered, value);
//  {
//    std::unique_lock<std::mutex> pop_lock(pop_mutex);
//    EXPECT_TRUE(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(1), [&]()->bool {
//        return cur_idx == 1;
//    }));
//  }
//  EXPECT_EQ(1, cur_idx);
//
//  value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(2 * OneKB))));
//  key.data = Identity(crypto::Hash<crypto::SHA512>(value));
//  // Trigger pop...
//  EXPECT_NO_THROW(data_store_->Store(key, value));
//  {
//    std::unique_lock<std::mutex> pop_lock(pop_mutex);
//    EXPECT_TRUE(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(2), [&]()->bool {
//        return cur_idx == 3;
//    }));
//  }
//  EXPECT_EQ(3, cur_idx);
//  EXPECT_NO_THROW(recovered = data_store_->Get(key));
//  EXPECT_EQ(recovered, value);
//
//  EXPECT_TRUE(DeleteDirectory(data_buffer_path_));
//}

REGISTER_TYPED_TEST_CASE_P(DataStoreTest,
                           BEH_Constructor,
                           BEH_SetMaxDiskMemoryUsage,
                           BEH_RemoveDiskBuffer,
                           BEH_SuccessfulStore,
                           BEH_UnsuccessfulStore,
                           BEH_DeleteOnDiskBufferOverfill);

typedef ::testing::Types<DataBuffer> StoragePolicies;
INSTANTIATE_TYPED_TEST_CASE_P(Storage, DataStoreTest, StoragePolicies);


//
//TEST_F(DataBufferTest, BEH_AsyncPopOnDiskBufferOverfill) {
//  size_t cur_idx(0);
//  std::mutex pop_mutex;
//  std::condition_variable pop_cond_var;
//  std::vector<std::pair<Identity, NonEmptyString>> old_key_value_pairs,
//                                                   new_key_value_pairs;
//  DataBuffer::PopFunctor pop_functor([this, &old_key_value_pairs, &cur_idx, &pop_mutex,
//                                          &pop_cond_var](const Identity& key_popped,
//                                                         const NonEmptyString& value_popped) {
//        this->PopFunction(key_popped, value_popped, old_key_value_pairs,
//                          cur_idx, pop_mutex, pop_cond_var);
//      });
//  const size_t num_entries(6), num_memory_entries(1), num_disk_entries(6);
//  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
//  old_key_value_pairs = PopulateKVB(num_entries, num_memory_entries, num_disk_entries,
//                                    test_path, pop_functor);
//  EXPECT_EQ(0, cur_idx);
//
//  NonEmptyString value, recovered;
//  Identity key;
//  while (new_key_value_pairs.size() < num_entries) {
//    value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(OneKB))));
//    key = Identity(crypto::Hash<crypto::SHA512>(value));
//    new_key_value_pairs.push_back(std::make_pair(key, value));
//  }
//
//  std::vector<std::future<void> > async_operations;
//  for (auto key_value : new_key_value_pairs) {
//    value = key_value.second;
//    key = key_value.first;
//    async_operations.push_back(std::async(std::launch::async, [this, key, value] {
//                                                  data_buffer_->Store(key, value);
//                                              }));
//  }
//  {
//    std::unique_lock<std::mutex> pop_lock(pop_mutex);
//    EXPECT_TRUE(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(2), [&]()->bool {
//        return cur_idx == num_entries;
//    }));
//  }
//  for (auto key_value : new_key_value_pairs) {
//    EXPECT_NO_THROW(recovered = data_buffer_->Get(key_value.first));
//    EXPECT_EQ(key_value.second, recovered);
//  }
//  EXPECT_EQ(num_entries, cur_idx);
//
//  EXPECT_TRUE(DeleteDirectory(kv_buffer_path_));
//}
//
//TEST_F(DataBufferTest, BEH_AsyncNonPopOnDiskBufferOverfill) {
//  std::vector<std::pair<Identity, NonEmptyString>> old_key_value_pairs,
//                                                   new_key_value_pairs;
//  const size_t num_entries(6), num_memory_entries(0), num_disk_entries(6);
//  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
//  old_key_value_pairs = PopulateKVB(num_entries, num_memory_entries, num_disk_entries,
//                                    test_path, pop_functor_);
//
//  NonEmptyString value, recovered;
//  Identity key;
//  while (new_key_value_pairs.size() < num_entries) {
//    value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(OneKB))));
//    key = Identity(crypto::Hash<crypto::SHA512>(value));
//    new_key_value_pairs.push_back(std::make_pair(key, value));
//  }
//
//  std::vector<std::future<void>> async_stores;
//  for (auto key_value : new_key_value_pairs) {
//    value = key_value.second;
//    key = key_value.first;
//    async_stores.push_back(std::async(std::launch::async, [this, key, value] {
//                                                  data_buffer_->Store(key, value);
//                                              }));
//  }
//
//  // Check the new Store attempts all block pending some Deletes
//  for (auto& async_store : async_stores) {
//    auto status(async_store.wait_for(std::chrono::milliseconds(250)));
//    EXPECT_EQ(std::future_status::timeout, status);
//  }
//
//  std::vector<std::future<NonEmptyString>> async_gets;
//  for (auto key_value : new_key_value_pairs) {
//    async_gets.push_back(std::async(std::launch::async, [this, key_value] {
//                                                  return data_buffer_->Get(key_value.first);
//                                              }));
//  }
//
//  // Check Get attempts for the new Store values all block pending the Store attempts completing
//  for (auto& async_get : async_gets) {
//    auto status(async_get.wait_for(std::chrono::milliseconds(100)));
//    EXPECT_EQ(std::future_status::timeout, status);
//  }
//
//  // Delete the last new Store attempt before it has completed
//  EXPECT_NO_THROW(data_buffer_->Delete(new_key_value_pairs.back().first));
//
//  // Delete the old values to allow the new Store attempts to complete
//  for (auto key_value : old_key_value_pairs)
//    EXPECT_NO_THROW(data_buffer_->Delete(key_value.first));
//
//  for (size_t i(0); i != num_entries - 1; ++i) {
//    auto status(async_gets[i].wait_for(std::chrono::milliseconds(100)));
//    ASSERT_EQ(std::future_status::ready, status);
//    recovered = async_gets[i].get();
//    EXPECT_EQ(new_key_value_pairs[i].second, recovered);
//  }
//
//  auto status(async_gets.back().wait_for(std::chrono::milliseconds(100)));
//  EXPECT_EQ(std::future_status::ready, status);
//  EXPECT_TRUE(async_gets.back().has_exception());
//  EXPECT_THROW(async_gets.back().get(), std::exception);
//
//  EXPECT_TRUE(DeleteDirectory(kv_buffer_path_));
//}
//
//TEST_F(DataBufferTest, BEH_RandomAsync) {
//  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
//  kv_buffer_path_ = fs::path(*test_path / "kv_buffer");
//  DataBuffer::PopFunctor pop_functor(
//      [](const Identity& key, const NonEmptyString& value) {
//          LOG(kInfo) << "Pop called on " << Base32Substr(key.string())
//                     << "with value " << Base32Substr(value.string());
//      });
//  data_buffer_.reset(new DataBuffer(MemoryUsage(kDefaultMaxMemoryUsage),
//                                             DiskUsage(kDefaultMaxDiskUsage),
//                                             pop_functor,
//                                             kv_buffer_path_));
//
//  std::vector<std::pair<Identity, NonEmptyString>> key_value_pairs;
//  uint32_t events(RandomUint32() % 500);
//  std::vector<std::future<void>> future_stores, future_deletes;
//  std::vector<std::future<NonEmptyString>> future_gets;
//
//  for (uint32_t i = 0; i != events; ++i) {
//    NonEmptyString value(RandomAlphaNumericString((RandomUint32() % 300) + 1));
//    Identity key(crypto::Hash<crypto::SHA512>(value));
//    key_value_pairs.push_back(std::make_pair(key, value));
//
//    uint32_t event(RandomUint32() % 3);
//    switch (event) {
//      case 0: {
//        if (!key_value_pairs.empty()) {
//          Identity event_key(key_value_pairs[RandomUint32() % key_value_pairs.size()].first);
//          future_deletes.push_back(
//              std::async([this, event_key] { data_buffer_->Delete(event_key); }));  // NOLINT (Fraser)
//        } else {
//          future_deletes.push_back(std::async([this, key] { data_buffer_->Delete(key); }));  // NOLINT (Fraser)
//        }
//        break;
//      }
//      case 1: {
//        // uint32_t index(RandomUint32() % key_value_pairs.size());
//        uint32_t index(i);
//        Identity event_key(key_value_pairs[index].first);
//        NonEmptyString event_value(key_value_pairs[index].second);
//        future_stores.push_back(std::async([this, event_key, event_value] {
//                                    data_buffer_->Store(event_key, event_value);
//                                }));
//        break;
//      }
//      case 2: {
//        if (!key_value_pairs.empty()) {
//          Identity event_key(key_value_pairs[RandomUint32() % key_value_pairs.size()].first);
//          future_gets.push_back(
//              std::async([this, event_key] { return data_buffer_->Get(event_key); }));  // NOLINT (Fraser)
//        } else {
//          future_gets.push_back(std::async([this, key] { return data_buffer_->Get(key); }));  // NOLINT (Fraser)
//        }
//        break;
//      }
//    }
//  }
//
//  for (auto& future_store : future_stores)
//    EXPECT_NO_THROW(future_store.get());
//
//  for (auto& future_delete : future_deletes) {
//    if (future_delete.has_exception())
//      EXPECT_THROW(future_delete.get(), std::exception);
//    else
//      EXPECT_NO_THROW(future_delete.get());
//  }
//
//  for (auto& future_get : future_gets) {
//    if (future_get.has_exception()) {
//      EXPECT_THROW(future_get.get(), std::exception);
//    } else {
//      try {
//        NonEmptyString value(future_get.get());
//        typedef std::vector<std::pair<Identity, NonEmptyString>>::value_type value_type;  // NOLINT (Fraser)
//        auto it = std::find_if(key_value_pairs.begin(),
//                               key_value_pairs.end(),
//                               [this, &value](const value_type& key_value) {
//                                  return key_value.second == value;
//                               });
//        EXPECT_NE(key_value_pairs.end(), it);
//      }
//      catch(const std::exception& e) {
//        std::string msg(e.what());
//        LOG(kError) << msg;
//      }
//    }
//  }
//  // Need to destroy data_buffer_ so that test_path will be able to be deleted
//  data_buffer_.reset();
//}
//
//class DataBufferTestDiskMemoryUsage : public testing::TestWithParam<MaxMemoryDiskUsage> {
// protected:
//  DataBufferTestDiskMemoryUsage()
//      : max_memory_usage_(GetParam().first),
//        max_disk_usage_(GetParam().second),
//        pop_functor_(),
//        data_buffer_(new DataBuffer(max_memory_usage_, max_disk_usage_, pop_functor_)) {}
//  MemoryUsage max_memory_usage_;
//  DiskUsage max_disk_usage_;
//  DataBuffer::PopFunctor pop_functor_;
//  std::unique_ptr<DataBuffer> data_buffer_;
//};
//
//TEST_P(DataBufferTestDiskMemoryUsage, BEH_Store) {
//  uint64_t disk_usage(max_disk_usage_), memory_usage(max_memory_usage_),
//           total_usage(disk_usage + memory_usage);
//  while (total_usage != 0) {
//    NonEmptyString value(std::string(RandomAlphaNumericString(
//                      static_cast<uint32_t>(max_memory_usage_))));
//    Identity key(crypto::Hash<crypto::SHA512>(value));
//    EXPECT_NO_THROW(data_buffer_->Store(key, value));
//    NonEmptyString recovered;
//    EXPECT_NO_THROW(recovered = data_buffer_->Get(key));
//    EXPECT_EQ(value, recovered);
//    if (disk_usage != 0) {
//      disk_usage -= max_memory_usage_;
//      total_usage -= max_memory_usage_;
//    } else {
//      total_usage -= max_memory_usage_;
//    }
//  }
//}
//
//TEST_P(DataBufferTestDiskMemoryUsage, BEH_Delete) {
//  uint64_t disk_usage(max_disk_usage_), memory_usage(max_memory_usage_),
//           total_usage(disk_usage + memory_usage);
//  std::map<Identity, NonEmptyString> key_value_pairs;
//  while (total_usage != 0) {
//    NonEmptyString value(std::string(RandomAlphaNumericString(
//                      static_cast<uint32_t>(max_memory_usage_))));
//    Identity key(crypto::Hash<crypto::SHA512>(value));
//    key_value_pairs[key] = value;
//    EXPECT_NO_THROW(data_buffer_->Store(key, value));
//    if (disk_usage != 0) {
//      disk_usage -= max_memory_usage_;
//      total_usage -= max_memory_usage_;
//    } else {
//      total_usage -= max_memory_usage_;
//    }
//  }
//  NonEmptyString recovered;
//  for (auto key_value : key_value_pairs) {
//    Identity key(key_value.first);
//    EXPECT_NO_THROW(recovered = data_buffer_->Get(key));
//    EXPECT_EQ(key_value.second, recovered);
//    EXPECT_NO_THROW(data_buffer_->Delete(key));
//    EXPECT_THROW(recovered = data_buffer_->Get(key), std::exception);
//  }
//}
//
//INSTANTIATE_TEST_CASE_P(TestDataBuffer,
//                        DataBufferTestDiskMemoryUsage,
//                        testing::Values(std::make_pair(1, 2),
//                                        std::make_pair(1, 1024),
//                                        std::make_pair(8, 1024),
//                                        std::make_pair(1024, 2048),
//                                        std::make_pair(1024, 1024),
//                                        std::make_pair(16, 16 * 1024),
//                                        std::make_pair(32, 32),
//                                        std::make_pair(1000, 10000),
//                                        std::make_pair(10000, 1000000)));

}  // namespace test

}  // namespace data_store

}  // namespace maidsafe
