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
