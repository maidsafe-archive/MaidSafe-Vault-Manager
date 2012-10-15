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

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_CHUNK_MANAGER_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_CHUNK_MANAGER_H_

#include <chrono>
#include <functional>
#include <memory>
#include <string>

#include "boost/date_time/posix_time/posix_time.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/utils/fob.h"

namespace bs2 = boost::signals2;

namespace maidsafe {

namespace priv {

typedef crypto::TigerHash ChunkVersion;

namespace chunk_store {

class ChunkStore;

class ChunkManager {
 public:
  typedef bs2::signal<void(const ChunkId&, const int&)> ChunkStoredSig,
                                                        ChunkModifiedSig,
                                                        ChunkGotSig,
                                                        ChunkDeletedSig;

  static std::chrono::duration<int> kLockTimeout() { return std::chrono::minutes(1); }

  virtual ~ChunkManager() {}

  virtual void GetChunk(const ChunkId& name,
                        const ChunkVersion& local_version,
                        const Fob& fob,
                        bool lock) = 0;
  virtual void StoreChunk(const ChunkId& name, const Fob& fob) = 0;
  virtual void ModifyChunk(const ChunkId& name, const NonEmptyString& content, const Fob& fob) = 0;
  virtual void DeleteChunk(const ChunkId& name, const Fob& fob) = 0;

  virtual int64_t StorageSize() = 0;
  virtual int64_t StorageCapacity() = 0;

  ChunkGotSig& sig_chunk_got() { return sig_chunk_got_; }
  ChunkStoredSig& sig_chunk_stored() { return sig_chunk_stored_; }
  ChunkModifiedSig& sig_chunk_modified() { return sig_chunk_modified_; }
  ChunkDeletedSig& sig_chunk_deleted() { return sig_chunk_deleted_; }
  std::shared_ptr<ChunkStore> chunk_store() { return chunk_store_; }

  std::chrono::duration<int> lock_timeout() { return lock_timeout_; }
  void SetLockTimeout(const std::chrono::duration<int>& value) { lock_timeout_ = value; }

 protected:
  explicit ChunkManager(std::shared_ptr<ChunkStore> chunk_store)
      : sig_chunk_got_(),
        sig_chunk_stored_(),
        sig_chunk_modified_(),
        sig_chunk_deleted_(),
        chunk_store_(chunk_store),
        lock_timeout_(kLockTimeout()) {}
  ChunkGotSig sig_chunk_got_;
  ChunkStoredSig sig_chunk_stored_;
  ChunkModifiedSig sig_chunk_modified_;
  ChunkDeletedSig sig_chunk_deleted_;
  std::shared_ptr<ChunkStore> chunk_store_;
  std::chrono::duration<int> lock_timeout_;

 private:
  ChunkManager(const ChunkManager&);
  ChunkManager& operator=(const ChunkManager&);
};

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_CHUNK_MANAGER_H_
