/***************************************************************************************************
 *  Copyright 2013 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#ifndef MAIDSAFE_DATA_STORE_MEMORY_BUFFER_H_
#define MAIDSAFE_DATA_STORE_MEMORY_BUFFER_H_

#include <mutex>

#include "boost/circular_buffer.hpp"

#include "maidsafe/common/types.h"

#include "maidsafe/data_types/data_name_variant.h"

namespace maidsafe {
namespace data_store {

namespace test {

class MemoryBufferTest;

}  // namespace test


class MemoryBuffer {
 public:
  typedef DataNameVariant KeyType;
  typedef boost::circular_buffer<std::pair<KeyType, NonEmptyString>> MemoryBufferType;

  MemoryBuffer(MemoryUsage max_memory_usage);

  ~MemoryBuffer();
  
  void Store(const KeyType& key, const NonEmptyString& value);
  NonEmptyString Get(const KeyType& key);
  void Delete(const KeyType& key);

 private:
  MemoryBuffer(const MemoryBuffer&);
  MemoryBuffer& operator=(const MemoryBuffer&);

  MemoryBufferType::iterator Find(const KeyType& key);

  MemoryBufferType memory_buffer_;
  mutable std::mutex mutex_;
};

}  // namespace data_store
}  // namespace maidsafe


#endif  // MAIDSAFE_DATA_STORE_MEMORY_BUFFER_H_
