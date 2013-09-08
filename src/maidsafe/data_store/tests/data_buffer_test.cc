/*  Copyright 2013 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/data_store/data_buffer.h"

#include <memory>

#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/data_types/data_name_variant.h"


namespace fs = boost::filesystem;
namespace args = std::placeholders;

namespace maidsafe {

namespace data_store {

namespace test {

namespace {

typedef std::pair<uint64_t, uint64_t> MaxMemoryDiskUsage;
const uint64_t OneKB(1024);
const uint64_t kDefaultMaxMemoryUsage(1000);
const uint64_t kDefaultMaxDiskUsage(2000);
const uint32_t kMaxDataTagValue(14);

template<typename KeyType>
KeyType GenerateRandomKey() {
  return KeyType(RandomString(crypto::SHA512::DIGESTSIZE));
}

template<>
DataNameVariant GenerateRandomKey<DataNameVariant>() {
  Identity id(RandomString(crypto::SHA512::DIGESTSIZE));
  // Check the value of 'kMaxDataTagValue' is not too high
  GetDataNameVariant(static_cast<DataTagValue>(kMaxDataTagValue), id);

  DataTagValue tag_value(static_cast<DataTagValue>(RandomUint32() % kMaxDataTagValue));
  return GetDataNameVariant(tag_value, id);
}

template<typename KeyType>
KeyType GenerateKeyFromValue(const NonEmptyString& value) {
  return KeyType(crypto::Hash<crypto::SHA512>(value).string());
}

template<>
DataNameVariant GenerateKeyFromValue<DataNameVariant>(const NonEmptyString& value) {
  Identity id(crypto::Hash<crypto::SHA512>(value));
  // Check the value of 'kMaxDataTagValue' is not too high
  GetDataNameVariant(static_cast<DataTagValue>(kMaxDataTagValue), id);

  DataTagValue tag_value(static_cast<DataTagValue>(RandomUint32() % kMaxDataTagValue));
  return GetDataNameVariant(tag_value, id);
}

}  // unnamed namespace

template<typename KeyType>
class DataBufferTest : public testing::Test {
 protected:
  DataBufferTest()
      : max_memory_usage_(kDefaultMaxMemoryUsage),
        max_disk_usage_(kDefaultMaxDiskUsage),
        data_buffer_path_(),
        pop_functor_(),
        data_buffer_(new DataBuffer<KeyType>(max_memory_usage_, max_disk_usage_, pop_functor_)) {}

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
      EXPECT_TRUE(to_be_popped_key == key_popped);
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

  std::vector<std::pair<KeyType, NonEmptyString>> PopulateKVB(
      size_t num_entries,
      size_t num_memory_entries,
      size_t num_disk_entries,
      maidsafe::test::TestPath test_path,
      const typename DataBuffer<KeyType>::PopFunctor& pop_functor) {
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
      key = GenerateKeyFromValue<KeyType>(value);
      key_value_pairs.push_back(std::make_pair(key, value));
    }
    data_buffer_.reset(new DataBuffer<KeyType>(MemoryUsage(num_memory_entries * OneKB),
                                               DiskUsage(num_disk_entries * OneKB),
                                               pop_functor, data_buffer_path_));
    for (auto key_value : key_value_pairs) {
      EXPECT_NO_THROW(data_buffer_->Store(key_value.first, key_value.second));
      EXPECT_NO_THROW(recovered = data_buffer_->Get(key_value.first));
      EXPECT_EQ(key_value.second, recovered);
    }
    return key_value_pairs;
  }

  boost::filesystem::path GetkDiskBuffer(const DataBuffer<KeyType>& kvb) {
    return kvb.kDiskBuffer_;
  }

  std::string DebugKeyName(const KeyType& key) {
    return data_buffer_->DebugKeyName(key);
  }

  MemoryUsage max_memory_usage_;
  DiskUsage max_disk_usage_;
  fs::path data_buffer_path_;
  typename DataBuffer<KeyType>::PopFunctor pop_functor_;
  std::unique_ptr<DataBuffer<KeyType>> data_buffer_;
};

TYPED_TEST_CASE_P(DataBufferTest);

TYPED_TEST_P(DataBufferTest, BEH_Constructor) {
  EXPECT_NO_THROW(DataBuffer<TypeParam>(MemoryUsage(0), DiskUsage(0), this->pop_functor_));
  EXPECT_NO_THROW(DataBuffer<TypeParam>(MemoryUsage(1), DiskUsage(1), this->pop_functor_));
  EXPECT_THROW(DataBuffer<TypeParam>(MemoryUsage(1), DiskUsage(0), this->pop_functor_),
               std::exception);
  EXPECT_THROW(DataBuffer<TypeParam>(MemoryUsage(2), DiskUsage(1), this->pop_functor_),
               std::exception);
  EXPECT_THROW(DataBuffer<TypeParam>(MemoryUsage(200001), DiskUsage(200000), this->pop_functor_),
               std::exception);
  EXPECT_NO_THROW(DataBuffer<TypeParam>(MemoryUsage(199999), DiskUsage(200000),
                                        this->pop_functor_));
  // Create a path to a file, and check that this can't be used as the disk buffer path.
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  ASSERT_FALSE(test_path->empty());
  boost::filesystem::path file_path(*test_path / "File");
  ASSERT_TRUE(WriteFile(file_path, " "));
  EXPECT_THROW(DataBuffer<TypeParam>(MemoryUsage(199999), DiskUsage(200000), this->pop_functor_,
                                     file_path), std::exception);
  EXPECT_THROW(DataBuffer<TypeParam>(MemoryUsage(199999), DiskUsage(200000), this->pop_functor_,
                                     file_path / "base"), std::exception);

  boost::filesystem::path dir_path(*test_path / "Dir");
  EXPECT_NO_THROW(DataBuffer<TypeParam>(MemoryUsage(1), DiskUsage(1), this->pop_functor_,
                                        dir_path));
  ASSERT_TRUE(fs::exists(dir_path));

  boost::filesystem::path kvb_path;
  {
    DataBuffer<TypeParam> kvb(MemoryUsage(1), DiskUsage(1), this->pop_functor_);
    kvb_path = this->GetkDiskBuffer(kvb);
    ASSERT_TRUE(fs::exists(kvb_path));
  }
  ASSERT_FALSE(fs::exists(kvb_path));
}

TYPED_TEST_P(DataBufferTest, BEH_SetMaxDiskMemoryUsage) {
  EXPECT_NO_THROW(this->data_buffer_->SetMaxMemoryUsage(MemoryUsage(this->max_disk_usage_ - 1)));
  EXPECT_NO_THROW(this->data_buffer_->SetMaxMemoryUsage(MemoryUsage(this->max_disk_usage_)));
  EXPECT_THROW(this->data_buffer_->SetMaxMemoryUsage(MemoryUsage(this->max_disk_usage_ + 1)),
               std::exception);
  EXPECT_THROW(this->data_buffer_->SetMaxDiskUsage(DiskUsage(this->max_disk_usage_ - 1)),
               std::exception);
  EXPECT_NO_THROW(this->data_buffer_->SetMaxDiskUsage(DiskUsage(this->max_disk_usage_)));
  EXPECT_NO_THROW(this->data_buffer_->SetMaxDiskUsage(DiskUsage(this->max_disk_usage_ + 1)));
  EXPECT_THROW(this->data_buffer_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(-1))),
               std::exception);
  EXPECT_NO_THROW(this->data_buffer_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(1))));
  EXPECT_THROW(this->data_buffer_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(0))),
               std::exception);
  EXPECT_NO_THROW(this->data_buffer_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(1))));
  EXPECT_NO_THROW(this->data_buffer_->SetMaxMemoryUsage(MemoryUsage(static_cast<uint64_t>(0))));
  EXPECT_NO_THROW(this->data_buffer_->SetMaxDiskUsage(DiskUsage(static_cast<uint64_t>(0))));
  EXPECT_NO_THROW(
     this->data_buffer_->SetMaxDiskUsage(DiskUsage(std::numeric_limits<uint64_t>().max())));
  EXPECT_NO_THROW(
     this->data_buffer_->SetMaxMemoryUsage(MemoryUsage(std::numeric_limits<uint64_t>().max())));
  EXPECT_THROW(this->data_buffer_->SetMaxDiskUsage(DiskUsage(kDefaultMaxDiskUsage)),
               std::exception);
  EXPECT_NO_THROW(this->data_buffer_->SetMaxMemoryUsage(MemoryUsage(kDefaultMaxMemoryUsage)));
  EXPECT_NO_THROW(this->data_buffer_->SetMaxDiskUsage(DiskUsage(kDefaultMaxDiskUsage)));
}

TYPED_TEST_P(DataBufferTest, BEH_RemoveDiskBuffer) {
  boost::system::error_code error_code;
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  fs::path kv_buffer_path(*test_path / "kv_buffer");
  const uintmax_t kMemorySize(1), kDiskSize(2);
  this->data_buffer_.reset(new DataBuffer<TypeParam>(MemoryUsage(kMemorySize), DiskUsage(kDiskSize),
                                                     this->pop_functor_, kv_buffer_path));
  auto key(GenerateRandomKey<TypeParam>());
  NonEmptyString small_value(std::string(kMemorySize, 'a'));
  EXPECT_NO_THROW(this->data_buffer_->Store(key, small_value));
  EXPECT_NO_THROW(this->data_buffer_->Delete(key));
  ASSERT_EQ(1, fs::remove_all(kv_buffer_path, error_code));
  ASSERT_FALSE(fs::exists(kv_buffer_path, error_code));
  // Fits into memory buffer successfully.  Background thread in future should throw, causing other
  // API functions to throw on next execution.
  EXPECT_NO_THROW(this->data_buffer_->Store(key, small_value));
  Sleep(std::chrono::seconds(1));
  EXPECT_THROW(this->data_buffer_->Store(key, small_value), std::exception);
  EXPECT_THROW(this->data_buffer_->Get(key), std::exception);
  EXPECT_THROW(this->data_buffer_->Delete(key), std::exception);

  this->data_buffer_.reset(new DataBuffer<TypeParam>(MemoryUsage(kMemorySize), DiskUsage(kDiskSize),
                                                     this->pop_functor_, kv_buffer_path));
  NonEmptyString large_value(std::string(kDiskSize, 'a'));
  EXPECT_NO_THROW(this->data_buffer_->Store(key, large_value));
  EXPECT_NO_THROW(this->data_buffer_->Delete(key));
  ASSERT_EQ(1, fs::remove_all(kv_buffer_path, error_code));
  ASSERT_FALSE(fs::exists(kv_buffer_path, error_code));
  // Skips memory buffer and goes straight to disk, causing exception.  Background thread in future
  // should finish, causing other API functions to throw on next execution.
  EXPECT_THROW(this->data_buffer_->Store(key, large_value), std::exception);
  EXPECT_THROW(this->data_buffer_->Get(key), std::exception);
  EXPECT_THROW(this->data_buffer_->Delete(key), std::exception);
}

TYPED_TEST_P(DataBufferTest, BEH_SuccessfulStore) {
  NonEmptyString value1(std::string(RandomAlphaNumericString(
                    static_cast<uint32_t>(this->max_memory_usage_))));
  auto key1(GenerateKeyFromValue<TypeParam>(value1));
  NonEmptyString value2(std::string(RandomAlphaNumericString(
      static_cast<uint32_t>(this->max_memory_usage_))));
  auto key2(GenerateKeyFromValue<TypeParam>(value2));
  EXPECT_NO_THROW(this->data_buffer_->Store(key1, value1));
  EXPECT_NO_THROW(this->data_buffer_->Store(key2, value2));
  NonEmptyString recovered = this->data_buffer_->Get(key1);
  EXPECT_EQ(recovered, value1);
  recovered = this->data_buffer_->Get(key2);
  EXPECT_EQ(recovered, value2);
}

TYPED_TEST_P(DataBufferTest, BEH_UnsuccessfulStore) {
  NonEmptyString value(std::string(static_cast<uint32_t>(this->max_disk_usage_ + 1), 'a'));
  auto key(GenerateKeyFromValue<TypeParam>(value));
  EXPECT_THROW(this->data_buffer_->Store(key, value), std::exception);
}

TYPED_TEST_P(DataBufferTest, BEH_DeleteOnDiskBufferOverfill) {
  const size_t num_entries(4), num_memory_entries(1), num_disk_entries(4);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  std::vector<std::pair<TypeParam, NonEmptyString>> key_value_pairs(this->PopulateKVB(num_entries,
      num_memory_entries, num_disk_entries, test_path, this->pop_functor_));
  NonEmptyString value, recovered;

  TypeParam first_key(key_value_pairs[0].first), second_key(key_value_pairs[1].first);
  value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(2 * OneKB))));
  auto key(GenerateKeyFromValue<TypeParam>(value));
  auto async = std::async(std::launch::async, [this, key, value] {
                                                  this->data_buffer_->Store(key, value);
                                              });
  EXPECT_THROW(recovered = this->data_buffer_->Get(key), std::exception);
  EXPECT_NO_THROW(this->data_buffer_->Delete(first_key));
  EXPECT_NO_THROW(this->data_buffer_->Delete(second_key));
  EXPECT_NO_THROW(async.wait());
  EXPECT_NO_THROW(recovered = this->data_buffer_->Get(key));
  EXPECT_EQ(recovered, value);

  EXPECT_TRUE(this->DeleteDirectory(this->data_buffer_path_));
}

TYPED_TEST_P(DataBufferTest, BEH_PopOnDiskBufferOverfill) {
  size_t cur_idx(0);
  std::mutex pop_mutex;
  std::condition_variable pop_cond_var;
  std::vector<std::pair<TypeParam, NonEmptyString>> key_value_pairs;
  typename DataBuffer<TypeParam>::PopFunctor pop_functor(
      [&](const TypeParam& key_popped, const NonEmptyString& value_popped) {
        this->PopFunction(key_popped, value_popped, key_value_pairs,
                          cur_idx, pop_mutex, pop_cond_var);
      });
  const size_t num_entries(4), num_memory_entries(1), num_disk_entries(4);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  key_value_pairs = this->PopulateKVB(num_entries, num_memory_entries, num_disk_entries,
                                      test_path, pop_functor);
  EXPECT_EQ(0, cur_idx);

  NonEmptyString value, recovered;
  value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(OneKB))));
  auto key(GenerateKeyFromValue<TypeParam>(value));
  // Trigger pop...
  EXPECT_NO_THROW(this->data_buffer_->Store(key, value));
  EXPECT_NO_THROW(recovered = this->data_buffer_->Get(key));
  EXPECT_EQ(recovered, value);
  {
    std::unique_lock<std::mutex> pop_lock(pop_mutex);
    EXPECT_TRUE(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(1), [&]()->bool {
        return cur_idx == 1;
    }));
  }
  EXPECT_EQ(1, cur_idx);

  value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(2 * OneKB))));
  key = GenerateKeyFromValue<TypeParam>(value);
  // Trigger pop...
  EXPECT_NO_THROW(this->data_buffer_->Store(key, value));
  {
    std::unique_lock<std::mutex> pop_lock(pop_mutex);
    EXPECT_TRUE(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(2), [&]()->bool {
        return cur_idx == 3;
    }));
  }
  EXPECT_EQ(3, cur_idx);
  EXPECT_NO_THROW(recovered = this->data_buffer_->Get(key));
  EXPECT_EQ(recovered, value);

  EXPECT_TRUE(this->DeleteDirectory(this->data_buffer_path_));
}

TYPED_TEST_P(DataBufferTest, BEH_AsyncPopOnDiskBufferOverfill) {
  size_t cur_idx(0);
  std::mutex pop_mutex;
  std::condition_variable pop_cond_var;
  std::vector<std::pair<TypeParam, NonEmptyString>> old_key_value_pairs, new_key_value_pairs;
  typename DataBuffer<TypeParam>::PopFunctor pop_functor(
      [&](const TypeParam& key_popped, const NonEmptyString& value_popped) {
        this->PopFunction(key_popped, value_popped, old_key_value_pairs,
                          cur_idx, pop_mutex, pop_cond_var);
      });
  const size_t num_entries(6), num_memory_entries(1), num_disk_entries(6);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  old_key_value_pairs = this->PopulateKVB(num_entries, num_memory_entries, num_disk_entries,
                                    test_path, pop_functor);
  EXPECT_EQ(0, cur_idx);

  NonEmptyString value, recovered;
  TypeParam key;
  while (new_key_value_pairs.size() < num_entries) {
    value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(OneKB))));
    key = GenerateKeyFromValue<TypeParam>(value);
    new_key_value_pairs.push_back(std::make_pair(key, value));
  }

  std::vector<std::future<void> > async_operations;
  for (auto key_value : new_key_value_pairs) {
    value = key_value.second;
    key = key_value.first;
    async_operations.push_back(std::async(std::launch::async, [this, key, value] {
                                                  this->data_buffer_->Store(key, value);
                                              }));
  }
  {
    std::unique_lock<std::mutex> pop_lock(pop_mutex);
    EXPECT_TRUE(pop_cond_var.wait_for(pop_lock, std::chrono::seconds(2), [&]()->bool {
        return cur_idx == num_entries;
    }));
  }
  for (auto key_value : new_key_value_pairs) {
    EXPECT_NO_THROW(recovered = this->data_buffer_->Get(key_value.first));
    EXPECT_EQ(key_value.second, recovered);
  }
  EXPECT_EQ(num_entries, cur_idx);

  EXPECT_TRUE(this->DeleteDirectory(this->data_buffer_path_));
}

TYPED_TEST_P(DataBufferTest, BEH_AsyncNonPopOnDiskBufferOverfill) {
  std::vector<std::pair<TypeParam, NonEmptyString>> old_key_value_pairs, new_key_value_pairs;
  const size_t num_entries(6), num_memory_entries(0), num_disk_entries(6);
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  old_key_value_pairs = this->PopulateKVB(num_entries, num_memory_entries, num_disk_entries,
                                    test_path, this->pop_functor_);

  NonEmptyString value, recovered;
  TypeParam key;
  while (new_key_value_pairs.size() < num_entries) {
    value = NonEmptyString(std::string(RandomAlphaNumericString(static_cast<uint32_t>(OneKB))));
    key = GenerateKeyFromValue<TypeParam>(value);
    new_key_value_pairs.push_back(std::make_pair(key, value));
  }

  std::vector<std::future<void>> async_stores;
  for (auto key_value : new_key_value_pairs) {
    value = key_value.second;
    key = key_value.first;
    async_stores.push_back(std::async(std::launch::async, [this, key, value] {
                                                  this->data_buffer_->Store(key, value);
                                              }));
  }

  // Check the new Store attempts all block pending some Deletes
  for (auto& async_store : async_stores) {
    auto status(async_store.wait_for(std::chrono::milliseconds(250)));
    EXPECT_EQ(std::future_status::timeout, status);
  }

  std::vector<std::future<NonEmptyString>> async_gets;
  for (auto key_value : new_key_value_pairs) {
    async_gets.push_back(std::async(std::launch::async, [this, key_value] {
                                                  return this->data_buffer_->Get(key_value.first);
                                              }));
  }

  // Check Get attempts for the new Store values all block pending the Store attempts completing
  for (auto& async_get : async_gets) {
    auto status(async_get.wait_for(std::chrono::milliseconds(100)));
    EXPECT_EQ(std::future_status::timeout, status);
  }

  // Delete the last new Store attempt before it has completed
  EXPECT_NO_THROW(this->data_buffer_->Delete(new_key_value_pairs.back().first));

  // Delete the old values to allow the new Store attempts to complete
  for (auto key_value : old_key_value_pairs)
    EXPECT_NO_THROW(this->data_buffer_->Delete(key_value.first));

  for (size_t i(0); i != num_entries - 1; ++i) {
    auto status(async_gets[i].wait_for(std::chrono::milliseconds(100)));
    ASSERT_EQ(std::future_status::ready, status);
    recovered = async_gets[i].get();
    EXPECT_EQ(new_key_value_pairs[i].second, recovered);
  }

  auto status(async_gets.back().wait_for(std::chrono::milliseconds(100)));
  EXPECT_EQ(std::future_status::ready, status);
  EXPECT_THROW(async_gets.back().get(), std::exception);

  EXPECT_TRUE(this->DeleteDirectory(this->data_buffer_path_));
}

TYPED_TEST_P(DataBufferTest, BEH_RepeatedlyStoreUsingSameKey) {
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  this->data_buffer_path_ = fs::path(*test_path / "data_buffer");
  typename DataBuffer<TypeParam>::PopFunctor pop_functor(
      [this](const TypeParam& key, const NonEmptyString& value) {
          LOG(kInfo) << "Pop called on " << this->DebugKeyName(key)
                     << "with value " << Base32Substr(value.string());
      });
  this->data_buffer_.reset(new DataBuffer<TypeParam>(MemoryUsage(kDefaultMaxMemoryUsage),
                                                     DiskUsage(kDefaultMaxDiskUsage),
                                                     pop_functor,
                                                     this->data_buffer_path_));
  NonEmptyString value(RandomAlphaNumericString((RandomUint32() % 30) + 1)), recovered, last_value;
  auto key(GenerateKeyFromValue<TypeParam>(value));
  auto async = std::async(std::launch::async, [this, key, value] {
                                                this->data_buffer_->Store(key, value);
                                              });
  EXPECT_NO_THROW(async.wait());
  EXPECT_EQ(true, async.valid());
  EXPECT_NO_THROW(async.get());
  EXPECT_NO_THROW(recovered = this->data_buffer_->Get(key));
  EXPECT_EQ(recovered, value);

  uint32_t events(RandomUint32() % 100);
  for (uint32_t i = 0; i != events; ++i) {
    last_value = value;
    while (last_value == value)
      last_value = NonEmptyString(RandomAlphaNumericString((RandomUint32() % 30) + 1));
    auto async = std::async(std::launch::async, [this, key, last_value] {
                                                  this->data_buffer_->Store(key, last_value);
                                                });
    EXPECT_NO_THROW(async.wait());
    EXPECT_EQ(true, async.valid());
    EXPECT_NO_THROW(async.get());
  }
  EXPECT_NO_THROW(recovered = this->data_buffer_->Get(key));
  EXPECT_NE(value, recovered);
  EXPECT_EQ(last_value, recovered);
  this->data_buffer_.reset();
  EXPECT_TRUE(this->DeleteDirectory(this->data_buffer_path_));
}

TYPED_TEST_P(DataBufferTest, BEH_RandomAsync) {
  maidsafe::test::TestPath test_path(maidsafe::test::CreateTestPath("MaidSafe_Test_DataBuffer"));
  this->data_buffer_path_ = fs::path(*test_path / "data_buffer");
  typename DataBuffer<TypeParam>::PopFunctor pop_functor(
      [this](const TypeParam& key, const NonEmptyString& value) {
          LOG(kInfo) << "Pop called on " << this->DebugKeyName(key)
                     << "with value " << Base32Substr(value.string());
      });
  this->data_buffer_.reset(new DataBuffer<TypeParam>(MemoryUsage(kDefaultMaxMemoryUsage),
                                                     DiskUsage(kDefaultMaxDiskUsage),
                                                     pop_functor,
                                                     this->data_buffer_path_));

  std::vector<std::pair<TypeParam, NonEmptyString>> key_value_pairs;
  uint32_t events(RandomUint32() % 500);
  std::vector<std::future<void>> future_stores, future_deletes;
  std::vector<std::future<NonEmptyString>> future_gets;

  for (uint32_t i = 0; i != events; ++i) {
    NonEmptyString value(RandomAlphaNumericString((RandomUint32() % 300) + 1));
    auto key(GenerateKeyFromValue<TypeParam>(value));
    key_value_pairs.push_back(std::make_pair(key, value));

    uint32_t event(RandomUint32() % 3);
    switch (event) {
      case 0: {
        if (!key_value_pairs.empty()) {
          TypeParam event_key(key_value_pairs[RandomUint32() % key_value_pairs.size()].first);
          future_deletes.push_back(
              std::async([this, event_key] { this->data_buffer_->Delete(event_key); }));
        } else {
          future_deletes.push_back(std::async([this, key] { this->data_buffer_->Delete(key); }));
        }
        break;
      }
      case 1: {
        // uint32_t index(RandomUint32() % key_value_pairs.size());
        uint32_t index(i);
        TypeParam event_key(key_value_pairs[index].first);
        NonEmptyString event_value(key_value_pairs[index].second);
        future_stores.push_back(std::async([this, event_key, event_value] {
                                    this->data_buffer_->Store(event_key, event_value);
                                }));
        break;
      }
      case 2: {
        if (!key_value_pairs.empty()) {
          TypeParam event_key(key_value_pairs[RandomUint32() % key_value_pairs.size()].first);
          future_gets.push_back(
              std::async([this, event_key] { return this->data_buffer_->Get(event_key); }));
        } else {
          future_gets.push_back(std::async([this, key] { return this->data_buffer_->Get(key); }));
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
    catch(const std::exception&) {}
  }

  for (auto& future_get : future_gets) {
    try {
      NonEmptyString value(future_get.get());
      typedef typename std::vector<std::pair<TypeParam, NonEmptyString>>::value_type value_type;
      auto it = std::find_if(key_value_pairs.begin(),
                              key_value_pairs.end(),
                              [this, &value](const value_type& key_value) {
                                return key_value.second == value;
                              });
      EXPECT_NE(key_value_pairs.end(), it);
    }
    catch(const std::exception& e) {
      std::string msg(e.what());
      LOG(kInfo) << msg;
    }
  }
  // Need to destroy data_buffer_ so that test_path will be able to be deleted
  this->data_buffer_.reset();
}

REGISTER_TYPED_TEST_CASE_P(DataBufferTest,
                           BEH_Constructor,
                           BEH_SetMaxDiskMemoryUsage,
                           BEH_RemoveDiskBuffer,
                           BEH_SuccessfulStore,
                           BEH_UnsuccessfulStore,
                           BEH_DeleteOnDiskBufferOverfill,
                           BEH_PopOnDiskBufferOverfill,
                           BEH_AsyncPopOnDiskBufferOverfill,
                           BEH_AsyncNonPopOnDiskBufferOverfill,
                           BEH_RepeatedlyStoreUsingSameKey,
                           BEH_RandomAsync);

typedef testing::Types<Identity, DataNameVariant, std::string> KeyTypes;
INSTANTIATE_TYPED_TEST_CASE_P(TypedKey, DataBufferTest, KeyTypes);



class DataBufferTestDiskMemoryUsage : public testing::TestWithParam<MaxMemoryDiskUsage> {
 protected:
  DataBufferTestDiskMemoryUsage()
      : max_memory_usage_(GetParam().first),
        max_disk_usage_(GetParam().second),
        pop_functor_(),
        data_buffer_(new DataBuffer<Identity>(max_memory_usage_, max_disk_usage_, pop_functor_)) {}
  MemoryUsage max_memory_usage_;
  DiskUsage max_disk_usage_;
  DataBuffer<Identity>::PopFunctor pop_functor_;
  std::unique_ptr<DataBuffer<Identity>> data_buffer_;
};

TEST_P(DataBufferTestDiskMemoryUsage, BEH_Store) {
  uint64_t disk_usage(max_disk_usage_), memory_usage(max_memory_usage_),
           total_usage(disk_usage + memory_usage);
  while (total_usage != 0) {
    NonEmptyString value(std::string(RandomAlphaNumericString(
                      static_cast<uint32_t>(max_memory_usage_))));
    Identity key(crypto::Hash<crypto::SHA512>(value));
    EXPECT_NO_THROW(data_buffer_->Store(key, value));
    NonEmptyString recovered;
    EXPECT_NO_THROW(recovered = data_buffer_->Get(key));
    EXPECT_EQ(value, recovered);
    if (disk_usage != 0) {
      disk_usage -= max_memory_usage_;
      total_usage -= max_memory_usage_;
    } else {
      total_usage -= max_memory_usage_;
    }
  }
}

TEST_P(DataBufferTestDiskMemoryUsage, BEH_Delete) {
  uint64_t disk_usage(max_disk_usage_), memory_usage(max_memory_usage_),
           total_usage(disk_usage + memory_usage);
  std::map<Identity, NonEmptyString> key_value_pairs;
  while (total_usage != 0) {
    NonEmptyString value(std::string(RandomAlphaNumericString(
                      static_cast<uint32_t>(max_memory_usage_))));
    Identity key(crypto::Hash<crypto::SHA512>(value));
    key_value_pairs[key] = value;
    EXPECT_NO_THROW(data_buffer_->Store(key, value));
    if (disk_usage != 0) {
      disk_usage -= max_memory_usage_;
      total_usage -= max_memory_usage_;
    } else {
      total_usage -= max_memory_usage_;
    }
  }
  NonEmptyString recovered;
  for (auto key_value : key_value_pairs) {
    Identity key(key_value.first);
    EXPECT_NO_THROW(recovered = data_buffer_->Get(key));
    EXPECT_EQ(key_value.second, recovered);
    EXPECT_NO_THROW(data_buffer_->Delete(key));
    EXPECT_THROW(recovered = data_buffer_->Get(key), std::exception);
  }
}

INSTANTIATE_TEST_CASE_P(TestDataBuffer,
                        DataBufferTestDiskMemoryUsage,
                        testing::Values(std::make_pair(1, 2),
                                        std::make_pair(1, 1024),
                                        std::make_pair(8, 1024),
                                        std::make_pair(1024, 2048),
                                        std::make_pair(1024, 1024),
                                        std::make_pair(16, 16 * 1024),
                                        std::make_pair(32, 32),
                                        std::make_pair(1000, 10000),
                                        std::make_pair(10000, 1000000)));

}  // namespace test

}  // namespace data_store

}  // namespace maidsafe
