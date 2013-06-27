/* Copyright 2013 MaidSafe.net limited

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
