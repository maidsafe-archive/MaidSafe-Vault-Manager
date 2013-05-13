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

#include "maidsafe/data_store/memory_buffer.h"

namespace maidsafe {
namespace data_store {

MemoryBuffer::MemoryBuffer(MemoryUsage max_memory_usage)
    : memory_buffer_(static_cast<uint32_t>(max_memory_usage.data)),
      mutex_() {}

MemoryBuffer::~MemoryBuffer() {}

void MemoryBuffer::Store(const KeyType& key, const NonEmptyString& value) {
  std::unique_lock<std::mutex> lock(mutex_);
  auto itr(Find(key));
  if (itr != memory_buffer_.end())
    memory_buffer_.erase(itr);
  memory_buffer_.push_back(std::make_pair(key, value));
}

NonEmptyString MemoryBuffer::Get(const KeyType& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(Find(key));
  if (itr != memory_buffer_.end())
    return itr->second;
  else
    ThrowError(CommonErrors::no_such_element);
  return NonEmptyString();
}

void MemoryBuffer::Delete(const KeyType& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  auto itr(Find(key));
  if (itr != memory_buffer_.end())
    memory_buffer_.erase(itr);
  else
    ThrowError(CommonErrors::no_such_element);
  return;
}

MemoryBuffer::MemoryBufferType::iterator MemoryBuffer::Find(const KeyType& key) {
  return std::find_if(memory_buffer_.begin(),
                      memory_buffer_.end(),
                      [&key](const MemoryBufferType::value_type& key_value) {
                          return key_value.first == key;
                      });
}

}  // namespace data_store
}  // namespace maidsafe
