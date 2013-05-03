/* Copyright (c) 2012 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "maidsafe/data_store/memory_buffer.h"
#include <string>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/data_store/utils.h"

namespace maidsafe {
namespace data_store {

MemoryBuffer::MemoryBuffer(MemoryUsage max_memory_usage)
    : memory_buffer_(static_cast<uint32_t>(max_memory_usage.data)),
      mutex_(),
      running_(true),
      worker_(),
      get_identity_visitor_() {
}

MemoryBuffer::~MemoryBuffer() {}

void MemoryBuffer::Store(const KeyType& key, const NonEmptyString& value) {
  std::unique_lock<std::mutex> lock(mutex_);
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
