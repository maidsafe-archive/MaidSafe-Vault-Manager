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

#ifndef MAIDSAFE_DATA_STORE_MEMORY_BUFFER_H_
#define MAIDSAFE_DATA_STORE_MEMORY_BUFFER_H_

#include <mutex>
#include <utility>

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

  explicit MemoryBuffer(MemoryUsage max_memory_usage);

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
