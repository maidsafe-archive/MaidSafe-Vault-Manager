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

#ifndef MAIDSAFE_DATA_STORE_DATA_STORE_H_
#define MAIDSAFE_DATA_STORE_DATA_STORE_H_

#include <deque>

#include "maidsafe/common/types.h"
#include "maidsafe/data_store/data_buffer.h"

namespace maidsafe {

namespace data_store {


namespace fs = boost::filesystem;

template<typename StoragePolicy>
class DataStore
  : public StoragePolicy {
 public:
  typedef typename StoragePolicy::KeyType KeyType;
  typedef typename StoragePolicy::PopFunctor PopFunctor;

  explicit DataStore(MemoryUsage max_memory_usage)
    : StoragePolicy(max_memory_usage) {}

  DataStore(MemoryUsage max_memory_usage, PopFunctor pop_functor)
    : StoragePolicy(max_memory_usage, pop_functor) {}

  explicit DataStore(DiskUsage max_disk_usage)
    : StoragePolicy(max_disk_usage) {}

  DataStore(DiskUsage max_disk_usage, PopFunctor pop_functor)
    : StoragePolicy(max_disk_usage, pop_functor) {}

  DataStore(DiskUsage max_disk_usage, PopFunctor pop_functor, const fs::path& disk_path)
    : StoragePolicy(max_disk_usage, pop_functor, disk_path) {}

  DataStore(MemoryUsage max_memory_usage, DiskUsage max_disk_usage, PopFunctor pop_functor)
    : StoragePolicy(max_memory_usage, max_disk_usage, pop_functor) {}

  DataStore(MemoryUsage max_memory_usage,
            DiskUsage max_disk_usage,
            PopFunctor pop_functor,
            const fs::path& disk_path)
    : StoragePolicy(max_memory_usage, max_disk_usage, pop_functor, disk_path) {}

  ~DataStore() {}

  void Store(const KeyType& key, const NonEmptyString& value) {
    StoragePolicy::Store(key, value);
  }
  NonEmptyString Get(const KeyType& key) {
    return StoragePolicy::Get(key);
  }
  void Delete(const KeyType& key) {
    StoragePolicy::Delete(key);
  }

  template<typename T>
  void Store(const T& key, const NonEmptyString& value) {
    StoragePolicy::Store(key, value);
  }
  template<typename T>
  NonEmptyString Get(const T& key) {
    return StoragePolicy::Get(key);
  }
  template<typename T>
  void Delete(const T& key) {
    StoragePolicy::Delete(key);
  }

 private:
  DataStore(const DataStore&);
  DataStore& operator=(const DataStore&);
};

}  // namespace data_store

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_STORE_DATA_STORE_H_
