/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#include "maidsafe/data_store/memory_buffer.h"

#include <memory>

#include "maidsafe/common/error.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "boost/mpl/size.hpp"

namespace maidsafe {
namespace data_store {
namespace test {

const uint64_t kDefaultMaxMemoryUsage(10);  // elements
const uint64_t OneKB(1024);

class MemoryBufferTest : public ::testing::Test {
 public:
  typedef MemoryBuffer::KeyType KeyType;
  typedef std::vector<std::pair<KeyType, NonEmptyString>> KeyValueContainer;

 protected:
  MemoryBufferTest()
    : memory_buffer_(new MemoryBuffer(MemoryUsage(kDefaultMaxMemoryUsage)))
  {}

  void SetUp() {}
  void TearDown() {}

  KeyType GetRandomKey() {
    // Currently 15 types are defined, but...
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
      case 12: return OwnerDirectory::name_type();
      case 13: return GroupDirectory::name_type();
      case 14: return WorldDirectory::name_type();
      // default:
        // Throw something!
      //  ;
    }
    return KeyType();
  }

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

  NonEmptyString GenerateKeyValueData(KeyType& key, uint32_t size) {
    GenerateKeyValuePair generate_key_value_pair_(size);
    return boost::apply_visitor(generate_key_value_pair_, key);
  }

  std::unique_ptr<MemoryBuffer> memory_buffer_;
};

TEST_F(MemoryBufferTest, BEH_Store) {
  KeyType key(GetRandomKey()), temp_key;
  NonEmptyString value = GenerateKeyValueData(key, OneKB), temp_value, recovered;

  EXPECT_NO_THROW(memory_buffer_->Store(key, value));
  // get first value...
  EXPECT_NO_THROW(recovered = memory_buffer_->Get(key));
  EXPECT_EQ(recovered, value);

  for (uint32_t i = 0; i != kDefaultMaxMemoryUsage - 1; ++i) {
    temp_key = GetRandomKey();
    temp_value = GenerateKeyValueData(temp_key, OneKB);
    EXPECT_NO_THROW(memory_buffer_->Store(temp_key, temp_value));
    EXPECT_NO_THROW(recovered = memory_buffer_->Get(temp_key));
    EXPECT_EQ(recovered, temp_value);
  }

  // get first value again...
  EXPECT_NO_THROW(recovered = memory_buffer_->Get(key));
  EXPECT_EQ(recovered, value);

  // store another value to replace first...
  temp_key = GetRandomKey();
  temp_value = GenerateKeyValueData(temp_key, OneKB);
  EXPECT_NO_THROW(memory_buffer_->Store(temp_key, temp_value));
  EXPECT_NO_THROW(recovered = memory_buffer_->Get(temp_key));
  EXPECT_EQ(recovered, temp_value);

  // try to get first value again...
  EXPECT_THROW(recovered = memory_buffer_->Get(key), maidsafe_error);
  EXPECT_NE(recovered, value);
  // should still equal last recovered value...
  EXPECT_EQ(recovered, temp_value);
}

TEST_F(MemoryBufferTest, BEH_Delete) {
  KeyValueContainer key_value_pairs;
  KeyType key;
  NonEmptyString value, recovered, temp(RandomAlphaNumericString(301));

  // store some key, value pairs...
  for (uint32_t i = 0; i != kDefaultMaxMemoryUsage; ++i) {
    key = GetRandomKey();
    value = GenerateKeyValueData(key, (RandomUint32() % 300) + 1);
    key_value_pairs.push_back(std::make_pair(key, value));
    EXPECT_NO_THROW(memory_buffer_->Store(key, value));
    EXPECT_NO_THROW(recovered = memory_buffer_->Get(key));
    EXPECT_EQ(recovered, value);
  }

  recovered = temp;

  // delete stored key, value pairs and check they're gone...
  for (uint32_t i = 0; i != kDefaultMaxMemoryUsage; ++i) {
    EXPECT_NO_THROW(memory_buffer_->Delete(key_value_pairs[i].first));
    EXPECT_THROW(recovered = memory_buffer_->Get(key_value_pairs[i].first), maidsafe_error);
    EXPECT_NE(recovered, key_value_pairs[i].second);
  }

  // re-store same key, value pairs...
  for (uint32_t i = 0; i != kDefaultMaxMemoryUsage; ++i) {
    EXPECT_NO_THROW(memory_buffer_->Store(key_value_pairs[i].first, key_value_pairs[i].second));
    EXPECT_NO_THROW(recovered = memory_buffer_->Get(key_value_pairs[i].first));
    EXPECT_EQ(recovered, key_value_pairs[i].second);
  }

  recovered = temp;

  // store some additional key, value pairs...
  for (uint32_t i = 0; i != kDefaultMaxMemoryUsage; ++i) {
    key = GetRandomKey();
    value = GenerateKeyValueData(key, (RandomUint32() % 300) + 1);
    key_value_pairs.push_back(std::make_pair(key, value));
    EXPECT_NO_THROW(memory_buffer_->Store(key, value));
    EXPECT_NO_THROW(recovered = memory_buffer_->Get(key));
    EXPECT_EQ(recovered, value);
  }

  recovered = temp;

  // check none of the original key, value pairs are present...
  for (uint32_t i = 0; i != kDefaultMaxMemoryUsage; ++i) {
    EXPECT_THROW(recovered = memory_buffer_->Get(key_value_pairs[i].first), maidsafe_error);
    EXPECT_NE(recovered, key_value_pairs[i].second);
  }

  // delete stored key, value pairs and check they're gone...
  for (uint32_t i = kDefaultMaxMemoryUsage; i != 2 * kDefaultMaxMemoryUsage; ++i) {
    EXPECT_NO_THROW(memory_buffer_->Delete(key_value_pairs[i].first));
    EXPECT_THROW(recovered = memory_buffer_->Get(key_value_pairs[i].first), maidsafe_error);
    EXPECT_NE(recovered, key_value_pairs[i].second);
  }
}

TEST_F(MemoryBufferTest, BEH_RepeatedlyStoreUsingSameKey) {
  const uint32_t size(50);
  KeyType key(GetRandomKey());
  NonEmptyString value = GenerateKeyValueData(key, (RandomUint32() % size) + 1),
                 recovered, last_value;
  auto async = std::async(std::launch::async, [this, key, value] {
                                                memory_buffer_->Store(key, value);
                                              });
  EXPECT_NO_THROW(async.wait());
  EXPECT_EQ(true, async.valid());
  EXPECT_NO_THROW(async.get());
  EXPECT_NO_THROW(recovered = memory_buffer_->Get(key));
  EXPECT_EQ(value, recovered);

  uint32_t events(RandomUint32() % (2 * size));
  for (uint32_t i = 0; i != events; ++i) {
    last_value = NonEmptyString(RandomAlphaNumericString((RandomUint32() % size) + 1));
    auto async = std::async(std::launch::async, [this, key, last_value] {
                                                  memory_buffer_->Store(key, last_value);
                                                });
    EXPECT_NO_THROW(async.wait());
    EXPECT_EQ(true, async.valid());
    EXPECT_NO_THROW(async.get());
  }

  EXPECT_NO_THROW(recovered = memory_buffer_->Get(key));
  EXPECT_NE(value, recovered);
  EXPECT_EQ(last_value, recovered);
}

TEST_F(MemoryBufferTest, BEH_RandomAsync) {
  typedef KeyValueContainer::value_type value_type;

  KeyValueContainer key_value_pairs;
  uint32_t events(RandomUint32() % 500);
  std::vector<std::future<void>> future_stores, future_deletes;
  std::vector<std::future<NonEmptyString>> future_gets;

  for (uint32_t i = 0; i != events; ++i) {
    KeyType key(GetRandomKey());
    NonEmptyString value = GenerateKeyValueData(key, (RandomUint32() % 300) + 1);
    key_value_pairs.push_back(std::make_pair(key, value));

    uint32_t event(RandomUint32() % 3);
    switch (event) {
      case 0: {
        if (!key_value_pairs.empty()) {
          KeyType event_key(key_value_pairs[RandomUint32() % key_value_pairs.size()].first);
          future_deletes.push_back(std::async([this, event_key] {
                                                memory_buffer_->Delete(event_key);
                                             }));
        } else {
          future_deletes.push_back(std::async([this, key] {
                                                memory_buffer_->Delete(key);
                                              }));
        }
        break;
      }
      case 1: {
        uint32_t index(i);
        KeyType event_key(key_value_pairs[index].first);
        NonEmptyString event_value(key_value_pairs[index].second);
        future_stores.push_back(std::async([this, event_key, event_value] {
                                  memory_buffer_->Store(event_key, event_value);
                                }));
        break;
      }
      case 2: {
        if (!key_value_pairs.empty()) {
          KeyType event_key(key_value_pairs[RandomUint32() % key_value_pairs.size()].first);
          future_gets.push_back(std::async([this, event_key] {
                                              return memory_buffer_->Get(event_key);
                                          }));
        } else {
          future_gets.push_back(std::async([this, key] {
                                              return memory_buffer_->Get(key);
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
}

}  // namespace test
}  // namespace data_store
}  // namespace maidsafe
