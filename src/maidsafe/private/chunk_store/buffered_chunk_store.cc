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

#include "maidsafe/private/chunk_store/buffered_chunk_store.h"

#include <chrono>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/chunk_store/file_chunk_store.h"
#include "maidsafe/private/chunk_store/memory_chunk_store.h"
#include "maidsafe/private/chunk_store/threadsafe_chunk_store.h"

namespace maidsafe {

namespace priv {

namespace chunk_store {

// If the cache is full and there are no more chunks left to delete, this is the
// number of chunk transfers to wait for (in Store) before the next check.
const int kWaitTransfersForCacheVacantCheck(10);
const std::chrono::seconds kXferWaitTimeout(3);

BufferedChunkStore::BufferedChunkStore(boost::asio::io_service& asio_service)  // NOLINT (Fraser)
    : ChunkStore(),
      cache_mutex_(),
      xfer_mutex_(),
      xfer_cond_var_(),
      asio_service_(asio_service),
      internal_perm_chunk_store_(new FileChunkStore),
      cache_chunk_store_(new MemoryChunkStore),
      perm_chunk_store_(new ThreadsafeChunkStore(internal_perm_chunk_store_)),
      cached_chunks_(),
      removable_chunks_(),
      pending_xfers_(),
      perm_size_(0),
      initialised_(false) {}

BufferedChunkStore::~BufferedChunkStore() {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
        return pending_xfers_.empty() || asio_service_.stopped();
      })) {
    LOG(kError) << "~BufferedChunkStore - Timed out.";
  }
}

bool BufferedChunkStore::Init(const fs::path& storage_location,
                              std::list<ChunkId> removable_chunks,
                              unsigned int dir_depth) {
  if (!internal_perm_chunk_store_->Init(storage_location, dir_depth)) {
    LOG(kError) << "Failed to initialise internal permanent chunk store.";
    return false;
  }

  perm_size_ = internal_perm_chunk_store_->Size();
  removable_chunks_ = removable_chunks;
  initialised_ = true;
  return true;
}

std::string BufferedChunkStore::Get(const ChunkId& name) const {
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    if (cache_chunk_store_->Has(name)) {
      auto it = std::find(cached_chunks_.begin(), cached_chunks_.end(), name);
      if (it != cached_chunks_.end()) {
        cached_chunks_.erase(it);
        cached_chunks_.push_front(name);
      }
      return cache_chunk_store_->Get(name);
    }
  }

  std::string content(perm_chunk_store_->Get(name));
  if (!content.empty() && DoCacheStore(name, content))
    AddCachedChunksEntry(name);
  return content;
}

bool BufferedChunkStore::Get(const ChunkId& name, const fs::path& sink_file_name) const {
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    if (cache_chunk_store_->Has(name)) {
      auto it = std::find(cached_chunks_.begin(), cached_chunks_.end(), name);
      if (it != cached_chunks_.end()) {
        cached_chunks_.erase(it);
        cached_chunks_.push_front(name);
      }
      return cache_chunk_store_->Get(name, sink_file_name);
    }
  }

  std::string content(perm_chunk_store_->Get(name));
  if (!content.empty() && DoCacheStore(name, content))
    AddCachedChunksEntry(name);
  return !content.empty() && WriteFile(sink_file_name, content);
}

bool BufferedChunkStore::Store(const ChunkId& name, const std::string& content) {
  if (!DoCacheStore(name, content)) {
    LOG(kError) << "Failed to cache: " << Base32Substr(name);
    return false;
  }

  if (!MakeChunkPermanent(name, content.size())) {
    // AddCachedChunksEntry(name);
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_chunk_store_->Delete(name);
    LOG(kError) << "Failed to make chunk permanent: " << Base32Substr(name);
    return false;
  }

  return true;
}

bool BufferedChunkStore::Store(const ChunkId& name,
                               const fs::path& source_file_name,
                               bool delete_source_file) {
  name.string();  // to ensure name is initialised (will throw otherwise)
  boost::system::error_code ec;
  uintmax_t size(source_file_name.empty() ? 0 : fs::file_size(source_file_name, ec));
  if (ec) {
    LOG(kError) << "Store - non-existent file passed: " << ec.message();
    return false;
  }

  if (!DoCacheStore(name, size, source_file_name, false)) {
    LOG(kError) << "Failed to cache: " << Base32Substr(name);
    return false;
  }

  if (!MakeChunkPermanent(name, size)) {
    // AddCachedChunksEntry(name);
    std::lock_guard<std::mutex> lock(cache_mutex_);
    cache_chunk_store_->Delete(name);
    LOG(kError) << "Failed to make chunk permanent: " << Base32Substr(name);
    return false;
  }

  if (delete_source_file)
    fs::remove(source_file_name, ec);

  return true;
}

bool BufferedChunkStore::CacheStore(const ChunkId& name, const std::string& content) {
  if (!DoCacheStore(name, content)) {
    LOG(kError) << "Failed to cache: " << Base32Substr(name);
    return false;
  }

  AddCachedChunksEntry(name);
  return true;
}

bool BufferedChunkStore::CacheStore(const ChunkId& name,
                                    const fs::path& source_file_name,
                                    bool delete_source_file) {
  boost::system::error_code ec;
  uintmax_t size(fs::file_size(source_file_name, ec));

  if (!DoCacheStore(name, size, source_file_name, false)) {
    LOG(kError) << "Failed to cache: " << Base32Substr(name);
    return false;
  }

  AddCachedChunksEntry(name);
  if (delete_source_file)
    fs::remove(source_file_name, ec);

  return true;
}

bool BufferedChunkStore::PermanentStore(const ChunkId& name) {
  std::string content;
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    content = cache_chunk_store_->Get(name);
  }

  {
    std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
    RemoveDeletionMarks(name);
    if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
          return pending_xfers_.find(name) == pending_xfers_.end();
        })) {
      LOG(kError) << "PermanentStore - Timed out storing " << Base32Substr(name)
                  << " while waiting for pending transfers.";
      return false;
    }
    if (perm_chunk_store_->Has(name))
      return true;
    if (content.empty() || !perm_chunk_store_->Store(name, content)) {
      LOG(kError) << "PermanentStore - Could not transfer " << Base32Substr(name);
      return false;
    }
    perm_size_ = perm_chunk_store_->Size();
  }

  return true;
}

bool BufferedChunkStore::Delete(const ChunkId& name) {
  bool file_delete_result(false);
  {
    std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
    if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
          return pending_xfers_.find(name) == pending_xfers_.end();
        })) {
      LOG(kError) << "Delete - Timed out deleting " << Base32Substr(name)
                  << " while waiting for pending transfers.";
      return false;
    }
    file_delete_result = perm_chunk_store_->Delete(name);
    perm_size_ = perm_chunk_store_->Size();
  }

  if (!file_delete_result)
    LOG(kError) << "Delete - Could not delete " << Base32Substr(name);

  std::lock_guard<std::mutex> lock(cache_mutex_);
  auto it = std::find(cached_chunks_.begin(), cached_chunks_.end(), name);
  if (it != cached_chunks_.end())
    cached_chunks_.erase(it);
  cache_chunk_store_->Delete(name);

  return file_delete_result;
}

bool BufferedChunkStore::Modify(const ChunkId& name, const std::string& content) {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  RemoveDeletionMarks(name);

  if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
        return pending_xfers_.find(name) == pending_xfers_.end();
      })) {
    LOG(kError) << "Modify - Timed out modifying " << Base32Substr(name)
                << " while waiting for pending transfers.";
    return false;
  }

  if (perm_chunk_store_->Has(name)) {
    std::string current_perm_content(perm_chunk_store_->Get(name));
    uintmax_t content_size_difference(0);
    bool increase_size(false);
    if (content.size() > current_perm_content.size()) {
      content_size_difference = content.size() - current_perm_content.size();
      increase_size = true;
      if (perm_chunk_store_->Capacity() > 0) {  // Check if Perm Chunk Store Size is Infinite
        // Wait For Space in Perm Store
        while (perm_size_ + content_size_difference > perm_chunk_store_->Capacity()) {
          if (removable_chunks_.empty()) {
            LOG(kError) << "Modify - Can't make space for changes to " << Base32Substr(name);
            return false;
          }
          if (perm_chunk_store_->Delete(removable_chunks_.front()))
            perm_size_ = perm_chunk_store_->Size();
          removable_chunks_.pop_front();
        }
      }
    } else {
      content_size_difference = current_perm_content.size() - content.size();
      increase_size = false;
    }
    if (perm_chunk_store_->Modify(name, content)) {
      if (increase_size)
        perm_size_ += content_size_difference;
      else
        perm_size_ -= content_size_difference;
      {
        std::lock_guard<std::mutex> lock(cache_mutex_);
        auto it = std::find(cached_chunks_.begin(), cached_chunks_.end(), name);
        if (it != cached_chunks_.end()) {
          cached_chunks_.erase(it);
          cache_chunk_store_->Delete(name);
        }
      }
      return true;
    } else {
      LOG(kError) << "Modify - Couldn't modify " << Base32Substr(name);
      return false;
    }
  } else {
    std::string current_cache_content;
    {
      std::unique_lock<std::mutex> lock(cache_mutex_);
      if (!cache_chunk_store_->Has(name)) {
        LOG(kError) << "Modify - Don't have chunk " << Base32Substr(name);
        return false;
      }

      current_cache_content = cache_chunk_store_->Get(name);
      uintmax_t content_size_difference(0);
      if (content.size() > current_cache_content.size()) {
        content_size_difference = content.size() - current_cache_content.size();
        // Make space in Cache if Needed
        while (!cache_chunk_store_->Vacant(content_size_difference)) {
          if (cached_chunks_.empty()) {
            lock.unlock();
            if (pending_xfers_.empty()) {
              LOG(kError) << "Modify - Can't make space for changes to "
                          << Base32Substr(name);
              return false;
            }

            int limit(kWaitTransfersForCacheVacantCheck);
            if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
                  return pending_xfers_.empty() || (--limit) <= 0;
                })) {
              LOG(kError) << "Modify - Timed out modifying " << Base32Substr(name)
                          << " while waiting for pending transfers.";
              return false;
            }
            lock.lock();
          }
          cache_chunk_store_->Delete(cached_chunks_.back());
          cached_chunks_.pop_back();
        }
      }
      return cache_chunk_store_->Modify(name, content);
    }
  }
}

bool BufferedChunkStore::Modify(const ChunkId& name,
                                const fs::path& source_file_name,
                                bool delete_source_file) {
  if (source_file_name.empty()) {
    LOG(kError) << "Modify - No source file passed for " << Base32Substr(name);
    return false;
  }

  // TODO(Steve) implement optimized Modify for changes from file

  std::string content;
  if (!ReadFile(source_file_name, &content)) {
    LOG(kError) << "Modify - Couldn't read source file for " << Base32Substr(name);
    return false;
  }

  if (!Modify(name, content)) {
    LOG(kError) << "Modify - Couldn't modify " << Base32Substr(name);
    return false;
  }

  boost::system::error_code ec;
  if (delete_source_file)
    fs::remove(source_file_name, ec);
  return true;
}

bool BufferedChunkStore::Has(const ChunkId& name) const {
  return CacheHas(name) || PermanentHas(name);
}

bool BufferedChunkStore::MoveTo(const ChunkId& name, ChunkStore* sink_chunk_store) {
  bool chunk_moved(false);
  {
    std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
    if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
          return pending_xfers_.find(name) == pending_xfers_.end();
        })) {
      LOG(kError) << "MoveTo - Timed out moving " << Base32Substr(name)
                  << " while waiting for pending transfers.";
      return false;
    }
    chunk_moved = perm_chunk_store_->MoveTo(name, sink_chunk_store);
    perm_size_ = perm_chunk_store_->Size();
  }

  if (!chunk_moved) {
    LOG(kError) << "MoveTo - Could not move " << Base32Substr(name);
    return false;
  }

  std::lock_guard<std::mutex> lock(cache_mutex_);
  auto it = std::find(cached_chunks_.begin(), cached_chunks_.end(), name);
  if (it != cached_chunks_.end())
    cached_chunks_.erase(it);
  cache_chunk_store_->Delete(name);

  return true;
}

bool BufferedChunkStore::CacheHas(const ChunkId& name) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cache_chunk_store_->Has(name);
}

bool BufferedChunkStore::PermanentHas(const ChunkId& name) const {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
        return pending_xfers_.find(name) == pending_xfers_.end();
      })) {
    LOG(kError) << "PermanentHas - Timed out for " << Base32Substr(name)
                << " while waiting for pending transfers.";
    return false;
  }
  uintmax_t rem_count(0);
  for (auto it = removable_chunks_.begin(); it != removable_chunks_.end(); ++it) {
    if (*it == name)
      ++rem_count;
  }
  return perm_chunk_store_->Count(name) > rem_count;
}

uintmax_t BufferedChunkStore::Size(const ChunkId& name) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  if (cache_chunk_store_->Has(name))
    return cache_chunk_store_->Size(name);
  return perm_chunk_store_->Size(name);
}

uintmax_t BufferedChunkStore::Size() const {
  std::lock_guard<std::mutex> lock(xfer_mutex_);
  return perm_size_;
}

uintmax_t BufferedChunkStore::CacheSize() const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cache_chunk_store_->Size();
}

uintmax_t BufferedChunkStore::Capacity() const {
  std::lock_guard<std::mutex> lock(xfer_mutex_);
  return perm_chunk_store_->Capacity();
}

uintmax_t BufferedChunkStore::CacheCapacity() const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cache_chunk_store_->Capacity();
}

void BufferedChunkStore::SetCapacity(const uintmax_t& capacity) {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
        return pending_xfers_.empty();
      })) {
    LOG(kError) << "SetCapacity - Timed out waiting for pending transfers.";
    return;
  }
  perm_chunk_store_->SetCapacity(capacity);
}

void BufferedChunkStore::SetCacheCapacity(const uintmax_t& capacity) {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  cache_chunk_store_->SetCapacity(capacity);
}

bool BufferedChunkStore::Vacant(const uintmax_t& required_size) const {
  std::lock_guard<std::mutex> lock(xfer_mutex_);
  return perm_size_ + required_size <= perm_chunk_store_->Capacity();
}

bool BufferedChunkStore::CacheVacant(const uintmax_t& required_size) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cache_chunk_store_->Vacant(required_size);
}

uintmax_t BufferedChunkStore::Count(const ChunkId& name) const {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
        return pending_xfers_.find(name) == pending_xfers_.end();
      })) {
    LOG(kError) << "Count - Timed out for " << Base32Substr(name)
                << " while waiting for pending transfers.";
    return false;
  }
  return perm_chunk_store_->Count(name);
}

uintmax_t BufferedChunkStore::Count() const {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
        return pending_xfers_.empty();
      })) {
    LOG(kError) << "Count - Timed out waiting for pending transfers.";
    return false;
  }
  return perm_chunk_store_->Count();
}

uintmax_t BufferedChunkStore::CacheCount() const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cache_chunk_store_->Count();
}

bool BufferedChunkStore::Empty() const {
  return CacheEmpty() && perm_chunk_store_->Empty();
}

bool BufferedChunkStore::CacheEmpty() const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  return cache_chunk_store_->Empty();
}

void BufferedChunkStore::Clear() {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
        return pending_xfers_.empty();
      })) {
    LOG(kError) << "Clear - Timed out waiting for pending transfers.";
    return;
  }
  std::lock_guard<std::mutex> lock(cache_mutex_);
  cached_chunks_.clear();
  removable_chunks_.clear();
  cache_chunk_store_->Clear();
  perm_chunk_store_->Clear();
  perm_size_ = 0;
}

void BufferedChunkStore::CacheClear() {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
        return pending_xfers_.empty();
      })) {
    LOG(kError) << "CacheClear - Timed out waiting for pending transfers.";
    return;
  }
  std::lock_guard<std::mutex> lock(cache_mutex_);
  cached_chunks_.clear();
  cache_chunk_store_->Clear();
}

void BufferedChunkStore::MarkForDeletion(const ChunkId& name) {
  std::lock_guard<std::mutex> lock(xfer_mutex_);
  removable_chunks_.push_back(name);
}

// Ensure cache mutex is not locked.
void BufferedChunkStore::AddCachedChunksEntry(const ChunkId& name) const {
  std::lock_guard<std::mutex> lock(cache_mutex_);
  auto it = std::find(cached_chunks_.begin(), cached_chunks_.end(), name);
  if (it != cached_chunks_.end())
    cached_chunks_.erase(it);
  cached_chunks_.push_front(name);
}

bool BufferedChunkStore::DoCacheStore(const ChunkId& name, const std::string& content) const {
  std::unique_lock<std::mutex> lock(cache_mutex_);
  if (cache_chunk_store_->Has(name))
    return true;

  // Check whether cache has capacity to store chunk
  if (content.size() > cache_chunk_store_->Capacity() &&
      cache_chunk_store_->Capacity() > 0) {
    LOG(kError) << "DoCacheStore - Chunk " << Base32Substr(name) << " too big ("
                << BytesToBinarySiUnits(content.size()) << " vs. "
                << BytesToBinarySiUnits(cache_chunk_store_->Capacity()) << ").";
    return false;
  }

  // Make space in cache
  while (!cache_chunk_store_->Vacant(content.size())) {
    while (cached_chunks_.empty()) {
      lock.unlock();
      {
        std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
        if (pending_xfers_.empty()) {
          LOG(kError) << "DoCacheStore - Can't make space for " << Base32Substr(name);
          return false;
        }
        int limit(kWaitTransfersForCacheVacantCheck);
        if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
              return pending_xfers_.empty() || (--limit) <= 0;
            })) {
          LOG(kError) << "DoCacheStore - Timed out for " << Base32Substr(name)
                      << " while waiting for pending transfers.";
          return false;
        }
      }
      lock.lock();
    }
    cache_chunk_store_->Delete(cached_chunks_.back());
    cached_chunks_.pop_back();
  }

  return cache_chunk_store_->Store(name, content);
}

bool BufferedChunkStore::DoCacheStore(const ChunkId& name,
                                      const uintmax_t& size,
                                      const fs::path& source_file_name,
                                      bool delete_source_file) const {
  std::unique_lock<std::mutex> lock(cache_mutex_);
  if (cache_chunk_store_->Has(name))
    return true;

  // Check whether cache has capacity to store chunk
  if (size > cache_chunk_store_->Capacity() &&
      cache_chunk_store_->Capacity() > 0) {
    LOG(kError) << "DoCacheStore - Chunk " << Base32Substr(name) << " too big ("
                << BytesToBinarySiUnits(size) << " vs. "
                << BytesToBinarySiUnits(cache_chunk_store_->Capacity()) << ").";
    return false;
  }

  // Make space in cache
  while (!cache_chunk_store_->Vacant(size)) {
    while (cached_chunks_.empty()) {
      lock.unlock();
      {
        std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
        if (pending_xfers_.empty()) {
          LOG(kError) << "DoCacheStore - Can't make space for " << Base32Substr(name);
          return false;
        }
        int limit(kWaitTransfersForCacheVacantCheck);
        if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
              return pending_xfers_.empty() || (--limit) <= 0;
            })) {
          LOG(kError) << "DoCacheStore - Timed out for " << Base32Substr(name)
                      << " while waiting for pending transfers.";
          return false;
        }
      }
      lock.lock();
    }
    cache_chunk_store_->Delete(cached_chunks_.back());
    cached_chunks_.pop_back();
  }

  return cache_chunk_store_->Store(name, source_file_name, delete_source_file);
}

bool BufferedChunkStore::MakeChunkPermanent(const ChunkId& name, const uintmax_t& size) {
  std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
  if (!initialised_) {
    LOG(kError) << "MakeChunkPermanent - Can't make " << Base32Substr(name)
                << " permanent, not initialised.";
    return false;
  }

  RemoveDeletionMarks(name);

  // Check whether permanent store has capacity to store chunk
  if (perm_chunk_store_->Capacity() > 0) {
    if (size > perm_chunk_store_->Capacity()) {
      LOG(kError) << "MakeChunkPermanent - Chunk " << Base32Substr(name)
                  << " too big (" << BytesToBinarySiUnits(size) << " vs. "
                  << BytesToBinarySiUnits(perm_chunk_store_->Capacity()) << ").";
      return false;
    }

    bool is_new(true);
    if (perm_size_ + size > perm_chunk_store_->Capacity()) {
      if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
            return pending_xfers_.empty();
          })) {
        LOG(kError) << "MakeChunkPermanent - Timed out for "
                    << Base32Substr(name) << " waiting for pending transfers.";
        return false;
      }
      if (perm_chunk_store_->Has(name)) {
        is_new = false;
      } else {
        // Make space in permanent store
        while (perm_size_ + size > perm_chunk_store_->Capacity()) {
          if (removable_chunks_.empty()) {
            LOG(kError) << "MakeChunkPermanent - Can't make space for " << Base32Substr(name);
            return false;
          }
          if (perm_chunk_store_->Delete(removable_chunks_.front()))
            perm_size_ = perm_chunk_store_->Size();
          removable_chunks_.pop_front();
        }
      }
    }

    if (is_new)
      perm_size_ += size;  // account for chunk in transfer
  }

  pending_xfers_.insert(name);
  asio_service_.post([=] { DoMakeChunkPermanent(name); });  // NOLINT (Fraser)

  return true;
}

void BufferedChunkStore::DoMakeChunkPermanent(const ChunkId& name) {
  std::string content;
  {
    std::lock_guard<std::mutex> lock(cache_mutex_);
    content = cache_chunk_store_->Get(name);
  }

  if (content.empty()) {
    LOG(kError) << "DoMakeChunkPermanent - Could not get " << Base32Substr(name) << " from cache.";
  } else if (perm_chunk_store_->Store(name, content)) {
    AddCachedChunksEntry(name);
  } else {
    LOG(kError) << "DoMakeChunkPermanent - Could not store " << Base32Substr(name);
  }

  std::lock_guard<std::mutex> lock(xfer_mutex_);
  perm_size_ = perm_chunk_store_->Size();
  pending_xfers_.erase(pending_xfers_.find(name));
  xfer_cond_var_.notify_all();
}

void BufferedChunkStore::RemoveDeletionMarks(const ChunkId& name) {
  removable_chunks_.remove_if([&name](const ChunkId& id) { return name == id; });  // NOLINT (Fraser)
}

bool BufferedChunkStore::DeleteAllMarked() {
  bool delete_result(true);
  std::list<ChunkId> rem_chunks;
  {
    std::unique_lock<std::mutex> xfer_lock(xfer_mutex_);
    rem_chunks = removable_chunks_;
    removable_chunks_.clear();
    if (!xfer_cond_var_.wait_for(xfer_lock, kXferWaitTimeout, [&] {
          return pending_xfers_.empty();
        })) {
      LOG(kError) << "DeleteAllMarked - Timed out waiting for pending transfers.";
      return false;
    }
    for (auto it = rem_chunks.begin(); it != rem_chunks.end(); ++it) {
      if (!perm_chunk_store_->Delete(*it)) {
        delete_result = false;
        LOG(kError) << "DeleteAllMarked - Could not delete "
                    << Base32Substr(*it) << " from permanent store.";
      }
    }
    perm_size_ = perm_chunk_store_->Size();
  }

  std::lock_guard<std::mutex> lock(cache_mutex_);
  for (auto it = rem_chunks.begin(); it != rem_chunks.end(); ++it) {
    auto it2 = std::find(cached_chunks_.begin(), cached_chunks_.end(), *it);
    if (it2 != cached_chunks_.end())
      cached_chunks_.erase(it2);
    cache_chunk_store_->Delete(*it);
  }

  return delete_result;
}

std::list<ChunkId> BufferedChunkStore::GetRemovableChunks() const {
  std::lock_guard<std::mutex> lock(xfer_mutex_);
  return removable_chunks_;
}

std::vector<ChunkData> BufferedChunkStore::GetChunks() const {
  std::lock_guard<std::mutex> lock(xfer_mutex_);
  return internal_perm_chunk_store_->GetChunks();
}

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
