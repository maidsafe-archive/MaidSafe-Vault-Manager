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

#ifndef MAIDSAFE_DATA_STORE_DATA_BUFFER_H_
#define MAIDSAFE_DATA_STORE_DATA_BUFFER_H_

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <utility>
#include <deque>

#include "boost/filesystem/path.hpp"
#include "boost/variant.hpp"

#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/detail/config.h"


namespace maidsafe {

namespace data_store {

namespace test { class DataBufferTest; }

class DataBuffer {
 public:
  typedef boost::variant<TaggedValue<Identity, passport::detail::AnmidTag>,
                         TaggedValue<Identity, passport::detail::AnsmidTag>,
                         TaggedValue<Identity, passport::detail::AntmidTag>,
                         TaggedValue<Identity, passport::detail::AnmaidTag>,
                         TaggedValue<Identity, passport::detail::MaidTag>,
                         TaggedValue<Identity, passport::detail::PmidTag>,
                         TaggedValue<Identity, passport::detail::MidTag>,
                         TaggedValue<Identity, passport::detail::SmidTag>,
                         TaggedValue<Identity, passport::detail::TmidTag>,
                         TaggedValue<Identity, passport::detail::AnmpidTag>,
                         TaggedValue<Identity, passport::detail::MpidTag> > VariantType;

  typedef std::function<void(const Identity&, const NonEmptyString&)> PopFunctor;
  // Throws if max_memory_usage >= max_disk_usage.  Throws if a writable folder can't be created in
  // temp_directory_path().  Starts a background worker thread which copies values from memory to
  // disk.  If pop_functor is valid, the disk cache will pop excess items when it is full,
  // otherwise Store will block until there is space made via Delete calls.
  DataBuffer(MemoryUsage max_memory_usage, DiskUsage max_disk_usage, PopFunctor pop_functor);
  // Throws if max_memory_usage >= max_disk_usage.  Throws if a writable folder can't be created in
  // "disk_buffer".  Starts a background worker thread which copies values from memory to disk.  If
  // pop_functor is valid, the disk cache will pop excess items when it is full, otherwise Store
  // will block until there is space made via Delete calls.
  DataBuffer(MemoryUsage max_memory_usage,
             DiskUsage max_disk_usage,
             PopFunctor pop_functor,
             const boost::filesystem::path& disk_buffer);
  ~DataBuffer();
  // Throws if the background worker has thrown (e.g. the disk has become inaccessible).  Throws if
  // the size of value is greater than the current specified maximum disk usage, or if the value
  // can't be written to disk (e.g. value is not initialised).  If there is not enough space to
  // store to memory, blocks until there is enough space to store to disk.  Space will be made
  // available via external calls to Delete, and also automatically if pop_functor_ is not NULL.
  template<typename DataType>
  void Store(const DataType& key, const NonEmptyString& value);
  // Throws if the background worker has thrown (e.g. the disk has become inaccessible).  Throws if
  // the value can't be read from disk.  If the value isn't in memory and has started to be stored
  // to disk, blocks while waiting for the storing to complete.
  template<typename DataType>
  NonEmptyString Get(const DataType& key);
  // Throws if the background worker has thrown (e.g. the disk has become inaccessible).  Throws if
  // the value was written to disk and can't be removed.
  template<typename DataType>
  void Delete(const DataType& key);
  // Throws if max_memory_usage > max_disk_usage_.
  void SetMaxMemoryUsage(MemoryUsage max_memory_usage);
  // Throws if max_memory_usage_ > max_disk_usage.
  void SetMaxDiskUsage(DiskUsage max_disk_usage);

  friend class test::DataBufferTest;

 private:
  DataBuffer(const DataBuffer&);
  DataBuffer& operator=(const DataBuffer&);

  struct VariantIdentityGetter : public boost::static_visitor<Identity>
  {
     template<typename T>
     Identity operator()(const T& t)
     {
        return t.value_type;
     }
  };

  template<typename UsageType, typename IndexType>
  struct Storage {
    typedef IndexType index_type;
    explicit Storage(UsageType max_in) : max(max_in), current(0), index(), mutex(), cond_var() {}  // NOLINT (Fraser)
    UsageType max, current;
    IndexType index;
    std::mutex mutex;
    std::condition_variable cond_var;
  };

  enum class StoringState { kNotStarted, kStarted, kCancelled, kCompleted };

  template<typename DataType>
  struct MemoryElement {
    MemoryElement(const DataType& key_in, const NonEmptyString& value_in)
        : key(key_in), value(value_in), also_on_disk(StoringState::kNotStarted) {}
    DataType key;
    NonEmptyString value;
    StoringState also_on_disk;
  };

  typedef std::deque<MemoryElement<VariantType> > MemoryIndex;

  template<typename DataType>
  struct DiskElement {
    explicit DiskElement(const DataType& key_in) : key(key_in), state(StoringState::kStarted) {}
    DataType key;
    StoringState state;
  };
  typedef std::deque<DiskElement<VariantType> > DiskIndex;

  void Init();

  template<typename DataType>
  bool StoreInMemory(const DataType& key, const NonEmptyString& value);

  void WaitForSpaceInMemory(const uint64_t& required_space,
                            std::unique_lock<std::mutex>& memory_store_lock);

  template<typename DataType>
  void StoreOnDisk(const DataType& key, const NonEmptyString& value);

  template<typename DataType>
  void WaitForSpaceOnDisk(const DataType& key,
                          const uint64_t& required_space,
                          std::unique_lock<std::mutex>& disk_store_lock,
                          bool& cancelled);

  template<typename DataType>
  void DeleteFromMemory(const DataType& key, StoringState& also_on_disk);

  template<typename DataType>
  void DeleteFromDisk(const DataType& key);

  template<typename DataType>
  void RemoveFile(const DataType& key, NonEmptyString* value);

  void CopyQueueToDisk();
  void CheckWorkerIsStillRunning();
  void StopRunning();
  boost::filesystem::path GetFilename(const Identity& key) const;

  template<typename T>
  bool HasSpace(const T& store, const uint64_t& required_space);

  template<typename T, typename DataType>
  typename T::index_type::iterator Find(T& store, const DataType& key);

  MemoryIndex::iterator FindOldestInMemoryOnly();
  MemoryIndex::iterator FindMemoryRemovalCandidate(const uint64_t& required_space,
                                                   std::unique_lock<std::mutex>& memory_store_lock);

  template<typename DataType>
  DiskIndex::iterator FindStartedToStoreOnDisk(const DataType& key);
  DiskIndex::iterator FindOldestOnDisk();

  template<typename DataType>
  DiskIndex::iterator FindAndThrowIfCancelled(const DataType& key);

  Storage<MemoryUsage, MemoryIndex> memory_store_;
  Storage<DiskUsage, DiskIndex> disk_store_;
  const PopFunctor kPopFunctor_;
  const boost::filesystem::path kDiskBuffer_;
  const bool kShouldRemoveRoot_;
  std::atomic<bool> running_;
  std::future<void> worker_;
};

}  // namespace data_store

}  // namespace maidsafe


#endif  // MAIDSAFE_DATA_STORE_DATA_BUFFER_H_
