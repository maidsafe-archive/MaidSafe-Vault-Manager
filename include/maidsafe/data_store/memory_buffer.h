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
