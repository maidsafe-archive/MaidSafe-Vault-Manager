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

#ifndef MAIDSAFE_PRIVATE_DATA_STORE_DATA_STORE_H_
#define MAIDSAFE_PRIVATE_DATA_STORE_DATA_STORE_H_

#include <deque>

#include "maidsafe/common/types.h"
#include "maidsafe/private/chunk_store/data_buffer.h"

namespace maidsafe {

namespace data_store {

class DataStore {
 public:
  DataStore(MemoryUsage max_memory_usage,
            DiskUsage max_disk_usage,
            DataBuffer::PopFunctor pop_functor);

  ~DataStore();

  template <typename DataType>
  void Store(const DataType& key, const NonEmptyString& value);

  template <typename DataType>
  NonEmptyString Get(const DataType& key);

  template <typename DataType>
  void Delete(const DataType& key);

  void SetMaxMemoryUsage(MemoryUsage max_memory_usage);
  void SetMaxDiskUsage(DiskUsage max_disk_usage);

 private:
  DataStore(const DataStore&);
  DataStore& operator=(const DataStore&);

  DataBuffer data_buffer_;
  std::deque<DataBuffer::VariantType> data_index_;
};

}  // namespace data_store

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DATA_STORE_DATA_STORE_H_
