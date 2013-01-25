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
#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "boost/mpl/size.hpp"

namespace fs = boost::filesystem;
namespace args = std::placeholders;

namespace maidsafe {

namespace data_store {

namespace test {

const uint64_t kDefaultMaxMemoryUsage(1000);
const uint64_t kDefaultMaxDiskUsage(2000);
const uint64_t OneKB(1024);

template <typename StoragePolicy>
class DataStoreTest : public ::testing::Test {
 public:
  typedef typename StoragePolicy::KeyType KeyType;
  typedef std::vector<std::pair<KeyType, NonEmptyString>> KeyValueContainer;
  typedef typename StoragePolicy::PopFunctor PopFunctor;

  struct GenerateKeyValuePair : public boost::static_visitor<NonEmptyString>
  {
    GenerateKeyValuePair() : size_(OneKB) {}
    explicit GenerateKeyValuePair(uint32_t size) : size_(size) {}

    template<typename T>
    NonEmptyString operator()(T& key)
    {
      NonEmptyString value = NonEmptyString(RandomAlphaNumericString(size_));
      key.data = Identity(crypto::Hash<crypto::SHA512>(value));
      return value;
    }

    uint32_t size_;
  };

  struct GetIdentity : public boost::static_visitor<Identity>
  {
    template<typename T>
    Identity operator()(T& key)
    {
      return key.data;
    }
  };


 protected:
  DataStoreTest()
    : max_memory_usage_(kDefaultMaxMemoryUsage),
      max_disk_usage_(kDefaultMaxDiskUsage),
      data_store_path_(),
      pop_functor_(),
      data_store_(new DataStore<StoragePolicy>(max_memory_usage_, max_disk_usage_, pop_functor_))
  {}

  void SetUp() {}
  void TearDown() {}

  void PopFunction(const KeyType& key,
                   const NonEmptyString& value,
                   const std::vector<std::pair<KeyType, NonEmptyString> >& key_value_pairs,
                   size_t& current_index,
                   std::mutex& pop_mutex,
                   std::condition_variable& pop_cond_var) {
    {
      std::unique_lock<std::mutex> lock(pop_mutex);
      KeyType compare_key(key_value_pairs[current_index].first);
      NonEmptyString compare_value(key_value_pairs[current_index].second);
      GetIdentity get_identity;
      Identity compare_key_id(boost::apply_visitor(get_identity, compare_key)),
               key_id(boost::apply_visitor(get_identity, key));
      EXPECT_EQ(compare_key_id, key_id);
      EXPECT_EQ(compare_value, value);
      ++current_index;
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

  KeyValueContainer PopulateDataStore(size_t num_entries,
                                      size_t num_memory_entries,
                                      size_t num_disk_entries,
                                      maidsafe::test::TestPath test_path,
                                      const PopFunctor& pop_functor) {
    boost::system::error_code error_code;
    data_store_path_ = fs::path(*test_path / "data_store");
    KeyValueContainer key_value_pairs;
    NonEmptyString value, recovered;
    KeyType key;

    EXPECT_TRUE(fs::create_directories(data_store_path_, error_code)) << data_store_path_ << ": "
                                                                      << error_code.message();
    EXPECT_EQ(0, error_code.value()) << data_store_path_ << ": " << error_code.message();
    EXPECT_TRUE(fs::exists(data_store_path_, error_code)) << data_store_path_ << ": "
                                                          << error_code.message();
    EXPECT_EQ(0, error_code.value());

    AddRandomKeyValuePairs(key_value_pairs, static_cast<uint32_t>(num_entries),
                           static_cast<uint32_t>(OneKB));

    data_store_.reset(new DataStore<StoragePolicy>(MemoryUsage(num_memory_entries * OneKB),
                                                   DiskUsage(num_disk_entries * OneKB),
                                                   pop_functor,
                                                   data_store_path_));
    for (auto key_value : key_value_pairs) {
      EXPECT_NO_THROW(data_store_->Store(key_value.first, key_value.second));
      EXPECT_NO_THROW(recovered = data_store_->Get(key_value.first));
      EXPECT_EQ(key_value.second, recovered);
    }
    return key_value_pairs;
  }

  boost::filesystem::path GetDiskStore(const DataStore<StoragePolicy>& data_store) {
    return data_store.kDiskBuffer_;
  }

  void AddRandomKeyValuePairs(KeyValueContainer& container, uint32_t number, uint32_t size) {
    // Currently there is 13 types defined, but do the calculation anyway...
    uint32_t number_of_types = boost::mpl::size<typename KeyType::types>::type::value,
             type_number;
    NonEmptyString value;
    for (uint32_t i = 0; i != number; ++i) {
      type_number = RandomUint32() % number_of_types;
      value = NonEmptyString(RandomAlphaNumericString(size));
      switch (type_number) {
        case 0: {
          passport::Anmid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 1: {
          passport::Ansmid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 2: {
          passport::Antmid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 3: {
          passport::Anmaid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 4: {
          passport::Maid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 5: {
          passport::Pmid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 6: {
          passport::Mid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 7: {
          passport::Smid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 8: {
          passport::Tmid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 9: {
          passport::Anmpid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 10: {
          passport::Mpid::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 11: {
          ImmutableData::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
        case 12: {
          MutableData::name_type key;
          key.data = Identity(crypto::Hash<crypto::SHA512>(value));
          container.push_back(std::make_pair(key, value));
          break;
        }
      }
    }
    return;
  }

  KeyType GetRandomKey() {
    // Currently 13 types are defined, but...
    uint32_t number_of_types = boost::mpl::size<typename KeyType::types>::type::value,
             type_number;
    type_number = RandomUint32() % number_of_types;
    switch (type_number) {
      case  0: return passport::Anmid::name_type();
      case  1: return passport::Ansmid::name_type();
      case  2: return passport::Antmid::name_type();
      case  3: return passport::Anmaid::name_type();
      case  4: return passport::Maid::name_type();
      case  5: return passport::Pmid::name_type();
      case  6: return passport::Mid::name_type();
      case  7: return passport::Smid::name_type();
      case  8: return passport::Tmid::name_type();
      case  9: return passport::Anmpid::name_type();
      case 10: return passport::Mpid::name_type();
      case 11: return ImmutableData::name_type();
      case 12: return MutableData::name_type();
      // default:
        // Throw something!
      //  ;
    }
    return KeyType();
  }

  NonEmptyString GenerateKeyValueData(KeyType& key, uint32_t size) {
    GenerateKeyValuePair generate_key_value_pair_(size);
    return boost::apply_visitor(generate_key_value_pair_, key);
  }

  MemoryUsage max_memory_usage_;
  DiskUsage max_disk_usage_;
  fs::path data_store_path_;
  PopFunctor pop_functor_;
  std::unique_ptr<DataStore<StoragePolicy>> data_store_;
};

TYPED_TEST_CASE_P(DataStoreTest);

TYPED_TEST_P(DataStoreTest, BEH_Constructor) {
  EXPECT_NO_THROW(DataStore<TypeParam>(MemoryUsage(0), DiskUsage(0), this->pop_functor_));
  EXPECT_NO_THROW(DataStore<TypeParam>(MemoryUsage(1), DiskUsage(1), this->pop_functor_));
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(1), DiskUsage(0), this->pop_functor_),
               std::exception);
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(2), DiskUsage(1), this->pop_functor_),
               std::exception);
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(200001), DiskUsage(200000), this->pop_functor_),
               std::exception);
  EXPECT_NO_THROW(DataStore<TypeParam>(MemoryUsage(199999), DiskUsage(200000), this->pop_functor_));
  // Create a path to a file, and check that this can't be used as the disk store path.
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  ASSERT_FALSE(test_path->empty());
  boost::filesystem::path file_path(*test_path / "File");
  ASSERT_TRUE(WriteFile(file_path, " "));
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(199999),
                                    DiskUsage(200000),
                                    this->pop_functor_,
                                    file_path),
               std::exception);
  EXPECT_THROW(DataStore<TypeParam>(MemoryUsage(199999),
                                    DiskUsage(200000),
                                    this->pop_functor_,
                                    file_path / "base"),
               std::exception);

  boost::filesystem::path dir_path(*test_path / "Dir");
  EXPECT_NO_THROW(DataStore<TypeParam>(MemoryUsage(1), DiskUsage(1), this->pop_functor_, dir_path));
  ASSERT_TRUE(fs::exists(dir_path));

  boost::filesystem::path data_store_path;
  {
    DataStore<TypeParam> data_store(MemoryUsage(1), DiskUsage(1), this->pop_functor_);
    data_store_path = this->GetDiskStore(data_store);
    ASSERT_TRUE(fs::exists(data_store_path));
  }
  ASSERT_FALSE(fs::exists(data_store_path));
}

TYPED_TEST_P(DataStoreTest, BEH_SetMaxDiskMemoryUsage) {
  EXPECT_NO_THROW(this->data_store_->SetMaxMemoryUsage(MemoryUsage(this->max_disk_usage_ - 1)));
  EXPECT_NO_THROW(this->data_store_->SetMaxMemoryUsage(MemoryUsage(this->max_disk_usage_)));
  EXPECT_THROW(
    this->data_store_->SetMaxMemoryUsage(MemoryUsage(this->max_disk_usage_ + 1)), std::exception);
  EXPECT_THROW(
    this->data_store_->SetMaxDiskUsage(DiskUsage(this->max_disk_usage_ - 1)), std::exception);
  EXPECT_NO_THROW(this->data_store_->SetMaxDiskUsage(DiskUsage(this->max_disk_usage_)));
  EXPECT_NO_THROW(this->data_store_->SetMaxDiskUsage(DiskUsage(this->max_disk_usage_ + 1)));
  EXPECT_THROW(
    this->data_store_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(-1))), std::exception);
  EXPECT_NO_THROW(this->data_store_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(1))));
  EXPECT_THROW(
    this->data_store_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(0))), std::exception);
  EXPECT_NO_THROW(this->data_store_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(1))));
  EXPECT_NO_THROW(this->data_store_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(0))));
  EXPECT_NO_THROW(this->data_store_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(0))));
  EXPECT_NO_THROW(
    this->data_store_->SetMaxDiskUsage(DiskUsage(std::numeric_limits<uint64_t>().max())));
  EXPECT_NO_THROW(
    this->data_store_->SetMaxMemoryUsage(MemoryUsage(std::numeric_limits<uint64_t>().max())));
  EXPECT_THROW(
    this->data_store_->SetMaxDiskUsage(DiskUsage(kDefaultMaxDiskUsage)), std::exception);
  EXPECT_NO_THROW(this->data_store_->SetMaxMemoryUsage(MemoryUsage(kDefaultMaxMemoryUsage)));
  EXPECT_NO_THROW(this->data_store_->SetMaxDiskUsage(DiskUsage(kDefaultMaxDiskUsage)));
}

TYPED_TEST_P(DataStoreTest, BEH_RemoveDiskStore) {
  typedef typename TypeParam::KeyType KeyType;

  boost::system::error_code error_code;
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  fs::path data_store_path(*test_path / "data_store");
  const uintmax_t kMemorySize(1), kDiskSize(2);
  this->data_store_.reset(new DataStore<TypeParam>(MemoryUsage(kMemorySize),
                                                   DiskUsage(kDiskSize),
                                                   this->pop_functor_,
                                                   data_store_path));
  KeyType key(this->GetRandomKey());
  NonEmptyString small_value = this->GenerateKeyValueData(key, kMemorySize);
  EXPECT_NO_THROW(this->data_store_->Store(key, small_value));
  EXPECT_NO_THROW(this->data_store_->Delete(key));
  ASSERT_EQ(1, fs::remove_all(data_store_path, error_code));
  ASSERT_FALSE(fs::exists(data_store_path, error_code));
  // Fits into memory store successfully.  Background thread in future should throw, causing other
  // API functions to throw on next execution.
  EXPECT_NO_THROW(this->data_store_->Store(key, small_value));
  Sleep(boost::posix_time::seconds(1));
  EXPECT_THROW(this->data_store_->Store(key, small_value), std::exception);
  EXPECT_THROW(this->data_store_->Get(key), std::exception);
  EXPECT_THROW(this->data_store_->Delete(key), std::exception);

  this->data_store_.reset(new DataStore<TypeParam>(MemoryUsage(kMemorySize),
                                                   DiskUsage(kDiskSize),
                                                   this->pop_functor_,
                                                   data_store_path));
  NonEmptyString large_value = this->GenerateKeyValueData(key, kDiskSize);
  EXPECT_NO_THROW(this->data_store_->Store(key, large_value));
  EXPECT_NO_THROW(this->data_store_->Delete(key));
  ASSERT_EQ(1, fs::remove_all(data_store_path, error_code));
  ASSERT_FALSE(fs::exists(data_store_path, error_code));
  // Skips memory store and goes straight to disk, causing exception.  Background thread in future
  // should finish, causing other API functions to throw on next execution.
  // - ADAPT TEST FOR MEMORY STORAGE ONLY!!!
  EXPECT_THROW(this->data_store_->Store(key, large_value), std::exception);
  EXPECT_THROW(this->data_store_->Get(key), std::exception);
  EXPECT_THROW(this->data_store_->Delete(key), std::exception);
}

TYPED_TEST_P(DataStoreTest, BEH_SuccessfulStore) {
  typedef typename TypeParam::KeyType KeyType;

  KeyType key1(this->GetRandomKey()), key2(this->GetRandomKey());
  NonEmptyString value1 = this->GenerateKeyValueData(key1,
                                               static_cast<uint32_t>(this->max_memory_usage_)),
                 value2 = this->GenerateKeyValueData(key2,
                                               static_cast<uint32_t>(this->max_memory_usage_)),
                 recovered;
  EXPECT_NO_THROW(this->data_store_->Store(key1, value1));
  EXPECT_NO_THROW(this->data_store_->Store(key2, value2));
  EXPECT_NO_THROW(recovered = this->data_store_->Get(key1));
  EXPECT_EQ(recovered, value1);
  EXPECT_NO_THROW(recovered = this->data_store_->Get(key2));
  EXPECT_EQ(recovered, value2);
}

TYPED_TEST_P(DataStoreTest, BEH_UnsuccessfulStore) {
  typedef typename TypeParam::KeyType KeyType;

  KeyType key(this->GetRandomKey());
  NonEmptyString value = this->GenerateKeyValueData(key,
                                              static_cast<uint32_t>(this->max_disk_usage_) + 1);
  EXPECT_THROW(this->data_store_->Store(key, value), std::exception);
}

TYPED_TEST_P(DataStoreTest, BEH_DeleteOnDiskStoreOverfill) {
  typedef typename DataStoreTest<TypeParam>::KeyValueContainer KeyValueContainer;
  typedef typename TypeParam::KeyType KeyType;

  const size_t num_entries(4), num_memory_entries(1), num_disk_entries(4);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  KeyValueContainer key_value_pairs(this->PopulateDataStore(num_entries,
                                                            num_memory_entries,
                                                            num_disk_entries,
                                                            test_path,
                                                            this->pop_functor_));
  KeyType key(this->GetRandomKey());
  NonEmptyString value = this->GenerateKeyValueData(key, 2 * OneKB), recovered;
  KeyType first_key(key_value_pairs[0].first), second_key(key_value_pairs[1].first);
  auto async = std::async(std::launch::async, [this, key, value] {
                                                  this->data_store_->Store(key, value);
                                              });
  EXPECT_THROW(recovered = this->data_store_->Get(key), std::exception);
  EXPECT_NO_THROW(this->data_store_->Delete(first_key));
  EXPECT_NO_THROW(this->data_store_->Delete(second_key));
  EXPECT_NO_THROW(async.wait());
  EXPECT_NO_THROW(recovered = this->data_store_->Get(key));
  EXPECT_EQ(recovered, value);

  EXPECT_TRUE(this->DeleteDirectory(this->data_store_path_));
}

TYPED_TEST_P(DataStoreTest, BEH_PopOnDiskStoreOverfill) {
  typedef typename DataStoreTest<TypeParam>::KeyValueContainer KeyValueContainer;
  typedef typename TypeParam::KeyType KeyType;
  typedef typename TypeParam::PopFunctor PopFunctor;

  size_t current_index(0);
  std::mutex pop_mutex;
  std::condition_variable pop_cond_var;
  KeyValueContainer key_value_pairs;
  PopFunctor pop_functor([this, &key_value_pairs, &current_index, &pop_mutex,
                    &pop_cond_var](const KeyType& key, const NonEmptyString& value) {
                        this->PopFunction(key,
                                          value,
                                          key_value_pairs,
                                          current_index,
                                          pop_mutex,
                                          pop_cond_var);
      });
  const size_t num_entries(4), num_memory_entries(1), num_disk_entries(4);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  key_value_pairs = this->PopulateDataStore(num_entries,
                                            num_memory_entries,
                                            num_disk_entries,
                                            test_path,
                                            pop_functor);
  EXPECT_EQ(0, current_index);

  KeyType key(this->GetRandomKey());
  NonEmptyString value = this->GenerateKeyValueData(key, OneKB), recovered;
  // Trigger pop...
  EXPECT_NO_THROW(this->data_store_->Store(key, value));
  EXPECT_NO_THROW(recovered = this->data_store_->Get(key));
  EXPECT_EQ(recovered, value);
  {
    std::unique_lock<std::mutex> pop_lock(pop_mutex);
    bool result(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(1), [&]()->bool {
                                        return current_index == 1;
                                      }));
    EXPECT_TRUE(result);
  }
  EXPECT_EQ(1, current_index);

  value = this->GenerateKeyValueData(key, 2 * OneKB);
  // Trigger pop...
  EXPECT_NO_THROW(this->data_store_->Store(key, value));
  {
    std::unique_lock<std::mutex> pop_lock(pop_mutex);
    bool result(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(2), [&]()->bool {
                                        return current_index == 3;
                                      }));
    EXPECT_TRUE(result);
  }
  EXPECT_EQ(3, current_index);
  EXPECT_NO_THROW(recovered = this->data_store_->Get(key));
  EXPECT_EQ(recovered, value);

  EXPECT_TRUE(this->DeleteDirectory(this->data_store_path_));
}

TYPED_TEST_P(DataStoreTest, BEH_AsyncDeleteOnDiskStoreOverfill) {
  typedef typename DataStoreTest<TypeParam>::KeyValueContainer KeyValueContainer;
  typedef typename TypeParam::KeyType KeyType;

  KeyValueContainer old_key_value_pairs, new_key_value_pairs;
  const size_t num_entries(6), num_memory_entries(0), num_disk_entries(6);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  old_key_value_pairs = this->PopulateDataStore(num_entries,
                                                num_memory_entries,
                                                num_disk_entries,
                                                test_path,
                                                this->pop_functor_);
  this->AddRandomKeyValuePairs(new_key_value_pairs, num_entries, OneKB);

  NonEmptyString value, recovered;
  KeyType key;
  std::vector<std::future<void>> async_stores;
  for (auto key_value : new_key_value_pairs) {
    value = key_value.second;
    key = key_value.first;
    async_stores.push_back(std::async(std::launch::async,
                                      [this, key, value] {
                                          this->data_store_->Store(key, value);
                                      }));
  }
  // Check the new Store attempts all block pending some Deletes
  for (auto& async_store : async_stores) {
    auto status(async_store.wait_for(std::chrono::milliseconds(250)));
    EXPECT_EQ(std::future_status::timeout, status);
  }

  std::vector<std::future<NonEmptyString>> async_gets;
  for (auto key_value : new_key_value_pairs) {
    async_gets.push_back(std::async(std::launch::async,
                                    [this, key_value] {
                                        return this->data_store_->Get(key_value.first);
                                    }));
  }
  // Check Get attempts for the new Store values all block pending the Store attempts completing
  for (auto& async_get : async_gets) {
    auto status(async_get.wait_for(std::chrono::milliseconds(100)));
    EXPECT_EQ(std::future_status::timeout, status);
  }
  // Delete the last new Store attempt before it has completed
  EXPECT_NO_THROW(this->data_store_->Delete(new_key_value_pairs.back().first));
  // Delete the old values to allow the new Store attempts to complete
  for (auto key_value : old_key_value_pairs)
    EXPECT_NO_THROW(this->data_store_->Delete(key_value.first));

  for (size_t i(0); i != num_entries - 1; ++i) {
    auto status(async_gets[i].wait_for(std::chrono::milliseconds(100)));
    ASSERT_EQ(std::future_status::ready, status);
    recovered = async_gets[i].get();
    EXPECT_EQ(new_key_value_pairs[i].second, recovered);
  }

  auto status(async_gets.back().wait_for(std::chrono::milliseconds(100)));
  EXPECT_EQ(std::future_status::ready, status);
  EXPECT_THROW(async_gets.back().get(), std::exception);
}

TYPED_TEST_P(DataStoreTest, BEH_AsyncPopOnDiskStoreOverfill) {
  typedef typename DataStoreTest<TypeParam>::KeyValueContainer KeyValueContainer;
  typedef typename TypeParam::KeyType KeyType;
  typedef typename TypeParam::PopFunctor PopFunctor;

  size_t current_index(0);
  std::mutex pop_mutex;
  std::condition_variable pop_cond_var;
  KeyValueContainer old_key_value_pairs, new_key_value_pairs;
  PopFunctor pop_functor([this, &old_key_value_pairs, &current_index, &pop_mutex,
                    &pop_cond_var](const KeyType& key, const NonEmptyString& value) {
                        this->PopFunction(key,
                                          value,
                                          old_key_value_pairs,
                                          current_index,
                                          pop_mutex,
                                          pop_cond_var);
      });
  const size_t num_entries(6), num_memory_entries(1), num_disk_entries(6);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  old_key_value_pairs = this->PopulateDataStore(num_entries,
                                                num_memory_entries,
                                                num_disk_entries,
                                                test_path,
                                                pop_functor);
  EXPECT_EQ(0, current_index);

  this->AddRandomKeyValuePairs(new_key_value_pairs, num_entries, OneKB);

  NonEmptyString value, recovered;
  KeyType key;
  std::vector<std::future<void> > async_operations;
  for (auto key_value : new_key_value_pairs) {
    value = key_value.second;
    key = key_value.first;
    async_operations.push_back(std::async(std::launch::async,
                                          [this, key, value] {
                                              this->data_store_->Store(key, value);
                                          }));
  }
  {
    std::unique_lock<std::mutex> pop_lock(pop_mutex);
    bool result(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(2),
                                      [&]()->bool {
                                        return current_index == num_entries;
                                      }));
    EXPECT_TRUE(result);
  }
  for (auto key_value : new_key_value_pairs) {
    EXPECT_NO_THROW(recovered = this->data_store_->Get(key_value.first));
    EXPECT_EQ(key_value.second, recovered);
  }
  EXPECT_EQ(num_entries, current_index);
}

TYPED_TEST_P(DataStoreTest, BEH_RepeatedlyStoreUsingSameKey) {
  typedef typename TypeParam::KeyType KeyType;
  typedef typename DataStoreTest<TypeParam>::GetIdentity GetIdentity;
  typedef typename TypeParam::PopFunctor PopFunctor;

  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  this->data_store_path_ = fs::path(*test_path / "data_store");
  PopFunctor pop_functor([this](const KeyType& key, const NonEmptyString& value) {
                            GetIdentity get_identity;
                            Identity key_id(boost::apply_visitor(get_identity, key));
                            LOG(kInfo) << "Pop called on " << Base32Substr(key_id.string())
                                       << "with value " << Base32Substr(value.string());
                        });
  this->data_store_.reset(new DataStore<TypeParam>(MemoryUsage(kDefaultMaxMemoryUsage),
                                                   DiskUsage(kDefaultMaxDiskUsage),
                                                   pop_functor,
                                                   this->data_store_path_));
  KeyType key(this->GetRandomKey());
  NonEmptyString value = this->GenerateKeyValueData(key, (RandomUint32() % 30) + 1),
                 recovered, last_value;
  auto async = std::async(std::launch::async, [this, key, value] {
                                                this->data_store_->Store(key, value);
                                              });
  EXPECT_NO_THROW(async.wait());
  EXPECT_EQ(true, async.valid());
  EXPECT_NO_THROW(async.get());
  EXPECT_NO_THROW(recovered = this->data_store_->Get(key));
  EXPECT_EQ(recovered, value);

  uint32_t events(RandomUint32() % 100);
  for (uint32_t i = 0; i != events; ++i) {
    last_value = NonEmptyString(RandomAlphaNumericString((RandomUint32() % 30) + 1));
    auto async = std::async(std::launch::async, [this, key, last_value] {
                                                  this->data_store_->Store(key, last_value);
                                                });
    EXPECT_NO_THROW(async.wait());
    EXPECT_EQ(true, async.valid());
    EXPECT_NO_THROW(async.get());
  }
  EXPECT_NO_THROW(recovered = this->data_store_->Get(key));
  EXPECT_NE(value, recovered);
  EXPECT_EQ(last_value, recovered);
  this->data_store_.reset();
  EXPECT_TRUE(this->DeleteDirectory(this->data_store_path_));
}

TYPED_TEST_P(DataStoreTest, BEH_RandomAsync) {
  typedef typename DataStoreTest<TypeParam>::KeyValueContainer KeyValueContainer;
  typedef typename KeyValueContainer::value_type value_type;
  typedef typename TypeParam::KeyType KeyType;
  typedef typename TypeParam::PopFunctor PopFunctor;
  typedef typename DataStoreTest<TypeParam>::GetIdentity GetIdentity;

  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  this->data_store_path_ = fs::path(*test_path / "data_store");
  PopFunctor pop_functor([this](const KeyType& key, const NonEmptyString& value) {
                            GetIdentity get_identity;
                            Identity key_id(boost::apply_visitor(get_identity, key));
                            LOG(kInfo) << "Pop called on " << Base32Substr(key_id.string())
                                       << "with value " << Base32Substr(value.string());
                        });
  this->data_store_.reset(new DataStore<TypeParam>(MemoryUsage(kDefaultMaxMemoryUsage),
                                                   DiskUsage(kDefaultMaxDiskUsage),
                                                   pop_functor,
                                                   this->data_store_path_));
  KeyValueContainer key_value_pairs;
  uint32_t events(RandomUint32() % 500);
  std::vector<std::future<void>> future_stores, future_deletes;
  std::vector<std::future<NonEmptyString>> future_gets;

  for (uint32_t i = 0; i != events; ++i) {
    KeyType key(this->GetRandomKey());
    NonEmptyString value = this->GenerateKeyValueData(key, (RandomUint32() % 300) + 1);
    key_value_pairs.push_back(std::make_pair(key, value));

    uint32_t event(RandomUint32() % 3);
    switch (event) {
      case 0: {
        if (!key_value_pairs.empty()) {
          KeyType event_key(key_value_pairs[RandomUint32() % key_value_pairs.size()].first);
          future_deletes.push_back(std::async([this, event_key] {
                                                this->data_store_->Delete(event_key);
                                             }));
        } else {
          future_deletes.push_back(std::async([this, key] {
                                                  this->data_store_->Delete(key);
                                              }));
        }
        break;
      }
      case 1: {
        // uint32_t index(RandomUint32() % key_value_pairs.size());
        uint32_t index(i);
        KeyType event_key(key_value_pairs[index].first);
        NonEmptyString event_value(key_value_pairs[index].second);
        future_stores.push_back(std::async([this, event_key, event_value] {
                                  this->data_store_->Store(event_key, event_value);
                                }));
        break;
      }
      case 2: {
        if (!key_value_pairs.empty()) {
          KeyType event_key(key_value_pairs[RandomUint32() % key_value_pairs.size()].first);
          future_gets.push_back(std::async([this, event_key] {
                                              return this->data_store_->Get(event_key);
                                          }));
        } else {
          future_gets.push_back(std::async([this, key] {
                                              return this->data_store_->Get(key);
                                          }));
        }
        break;
      }
    }
  }

  for (auto& future_store : future_stores)
    EXPECT_NO_THROW(future_store.get());

  for (auto& future_delete : future_deletes) {
    try {
      future_delete.get();
    }
    catch(const std::exception& e) {
      std::string msg(e.what());
      LOG(kError) << msg;
    }
  }

  for (auto& future_get : future_gets) {
    try {
      NonEmptyString value(future_get.get());
      auto it = std::find_if(key_value_pairs.begin(),
                             key_value_pairs.end(),
                             [this, &value](const value_type& key_value_pair) {
                                return key_value_pair.second == value;
                             });
      EXPECT_NE(key_value_pairs.end(), it);
    }
    catch(const std::exception& e) {
      std::string msg(e.what());
      LOG(kError) << msg;
    }
  }
  // Need to destroy data_store_ so that test_path will be able to be deleted
  this->data_store_.reset();
}

TYPED_TEST_P(DataStoreTest, BEH_Store) {
  typedef typename TypeParam::KeyType KeyType;

  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  std::vector<std::pair<uint32_t, uint32_t>> values;
  values.push_back(std::make_pair(1, 2));
  values.push_back(std::make_pair(1, 1024));
  values.push_back(std::make_pair(8, 1024));
  values.push_back(std::make_pair(1024, 2048));
  values.push_back(std::make_pair(1024, 1024));
  values.push_back(std::make_pair(16, 16 * 1024));
  values.push_back(std::make_pair(32, 32));
  values.push_back(std::make_pair(1000, 10000));
  values.push_back(std::make_pair(10000, 1000000));

  for (uint32_t i = 0; i != values.size(); ++i) {
    fs::path data_store_path(*test_path / "data_store");
    this->data_store_.reset(new DataStore<TypeParam>(MemoryUsage(values[i].first),
                                                     DiskUsage(values[i].second),
                                                     this->pop_functor_,
                                                     data_store_path));
    uint32_t disk_usage(values[i].second), memory_usage(values[i].first),
             total_usage(disk_usage + memory_usage);
    while (total_usage != 0) {
      KeyType key(this->GetRandomKey());
      NonEmptyString value = this->GenerateKeyValueData(key, memory_usage), recovered;
      EXPECT_NO_THROW(this->data_store_->Store(key, value));
      EXPECT_NO_THROW(recovered = this->data_store_->Get(key));
      EXPECT_EQ(value, recovered);
      if (disk_usage != 0) {
        disk_usage -= memory_usage;
        total_usage -= memory_usage;
      } else {
        total_usage -= memory_usage;
      }
    }
    this->data_store_.reset();
    EXPECT_TRUE(this->DeleteDirectory(data_store_path));
  }
}

TYPED_TEST_P(DataStoreTest, BEH_Delete) {
  typedef typename TypeParam::KeyType KeyType;

  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataStore"));
  std::vector<std::pair<uint32_t, uint32_t>> values;
  values.push_back(std::make_pair(1, 2));
  values.push_back(std::make_pair(1, 1024));
  values.push_back(std::make_pair(8, 1024));
  values.push_back(std::make_pair(1024, 2048));
  values.push_back(std::make_pair(1024, 1024));
  values.push_back(std::make_pair(16, 16 * 1024));
  values.push_back(std::make_pair(32, 32));
  values.push_back(std::make_pair(1000, 10000));
  values.push_back(std::make_pair(10000, 1000000));

  for (uint32_t i = 0; i != values.size(); ++i) {
    fs::path data_store_path(*test_path / "data_store");
    this->data_store_.reset(new DataStore<TypeParam>(MemoryUsage(values[i].first),
                                                     DiskUsage(values[i].second),
                                                     this->pop_functor_,
                                                     data_store_path));
    uint32_t disk_usage(values[i].second), memory_usage(values[i].first),
             total_usage(disk_usage + memory_usage);
    std::map<KeyType, NonEmptyString> key_value_pairs;
    while (total_usage != 0) {
      KeyType key(this->GetRandomKey());
      NonEmptyString value = this->GenerateKeyValueData(key, memory_usage);
      key_value_pairs[key] = value;
      EXPECT_NO_THROW(this->data_store_->Store(key, value));
      if (disk_usage != 0) {
        disk_usage -= memory_usage;
        total_usage -= memory_usage;
      } else {
        total_usage -= memory_usage;
      }
    }
    NonEmptyString recovered;
    for (auto key_value : key_value_pairs) {
      KeyType key(key_value.first);
      EXPECT_NO_THROW(recovered = this->data_store_->Get(key));
      EXPECT_EQ(key_value.second, recovered);
      EXPECT_NO_THROW(this->data_store_->Delete(key));
      EXPECT_THROW(recovered = this->data_store_->Get(key), std::exception);
    }
    this->data_store_.reset();
    EXPECT_TRUE(this->DeleteDirectory(data_store_path));
  }
}

REGISTER_TYPED_TEST_CASE_P(DataStoreTest,
                           BEH_Constructor,
                           BEH_SetMaxDiskMemoryUsage,
                           BEH_RemoveDiskStore,
                           BEH_SuccessfulStore,
                           BEH_UnsuccessfulStore,
                           BEH_DeleteOnDiskStoreOverfill,
                           BEH_PopOnDiskStoreOverfill,
                           BEH_AsyncDeleteOnDiskStoreOverfill,
                           BEH_AsyncPopOnDiskStoreOverfill,
                           BEH_RepeatedlyStoreUsingSameKey,
                           BEH_RandomAsync,
                           BEH_Store,
                           BEH_Delete);

typedef ::testing::Types<DataBuffer> StoragePolicies;
INSTANTIATE_TYPED_TEST_CASE_P(Storage, DataStoreTest, StoragePolicies);

}  // namespace test

}  // namespace data_store

}  // namespace maidsafe
