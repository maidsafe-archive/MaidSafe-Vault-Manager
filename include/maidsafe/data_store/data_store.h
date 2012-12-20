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

template<typename StoragePolicy>
class DataStore
  : public StoragePolicy {
 public:
  typedef typename StoragePolicy::PopFunctor PopFunctor;

  DataStore(MemoryUsage max_memory_usage,
            DiskUsage max_disk_usage,
            DataBuffer::PopFunctor pop_functor)
    : StoragePolicy(max_memory_usage, max_disk_usage, pop_functor) {}

  DataStore(MemoryUsage max_memory_usage,
            DiskUsage max_disk_usage,
            DataBuffer::PopFunctor pop_functor,
            const boost::filesystem::path& disk_path)
    : StoragePolicy(max_memory_usage, max_disk_usage, pop_functor, disk_path) {}

  ~DataStore() {}

  template<typename T, typename Tag>
  void Store(const TaggedValue<T, Tag>& key, const NonEmptyString& value) {
    StoragePolicy::Store(key, value);
  }
  template<typename T, typename Tag>
  NonEmptyString Get(const TaggedValue<T, Tag>& key) {
    return StoragePolicy::Get(key);
  }
  template<typename T, typename Tag>
  void Delete(const TaggedValue<T, Tag>& key) {
    StoragePolicy::Delete(key);
  }

  // void SetMaxMemoryUsage(MemoryUsage max_memory_usage);
  // void SetMaxDiskUsage(DiskUsage max_disk_usage);

 private:
  DataStore(const DataStore&);
  DataStore& operator=(const DataStore&);
};

}  // namespace data_store

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_STORE_DATA_STORE_H_
