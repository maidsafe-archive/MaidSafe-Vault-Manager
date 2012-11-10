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

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_REMOTE_CHUNK_STORE_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_REMOTE_CHUNK_STORE_H_

#include <chrono>
#include <condition_variable>
#include <functional>
#include <list>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <utility>

#include "boost/asio/io_service.hpp"
#include "boost/bimap.hpp"
#include "boost/bimap/list_of.hpp"
#include "boost/bimap/multiset_of.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_actions/chunk_id.h"
#include "maidsafe/private/utils/fob.h"

namespace bptime = boost::posix_time;
namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

typedef crypto::TigerHash ChunkVersion;

namespace chunk_actions { class ChunkActionAuthority; }

namespace chunk_store {

class BufferedChunkStore;
class ChunkManager;

class RemoteChunkStore {
 public:
  enum class OpType { kGet = 0, kGetLock, kStore, kModify, kDelete };

  // typedef std::function<void(std::string)> GetFunctor;  // NOLINT
  typedef std::function<void(bool)> OpFunctor;  // NOLINT

  typedef bs2::signal<void(size_t)> NumPendingOpsSig;
  typedef std::shared_ptr<NumPendingOpsSig> NumPendingOpsSigPtr;

  struct OperationData {
    OperationData()
        : op_type(),
          active(false),
          ready(false),
          fob(),
          local_version(),
          content(),
          callback() {}
    explicit OperationData(const OpType& op_type_in)
        : op_type(op_type_in),
          active(false),
          ready(false),
          fob(),
          local_version(),
          content(),
          callback() {}
    OperationData(const OpType& op_type_in,
                  const OpFunctor& callback_in,
                  const Fob& fob_in,
                  bool ready_in)
        : op_type(op_type_in),
          active(false),
          ready(ready_in),
          fob(fob_in),
          local_version(),
          content(),
          callback(callback_in) {}
    OpType op_type;
    bool active, ready;
    Fob fob;
    ChunkVersion local_version;
    NonEmptyString content;
    OpFunctor callback;
  };

  // typedef std::map<std::string, OperationData> OperationMap;
  typedef std::multimap<ChunkId, OpType> OperationMultiMap;
  /**
   * The OperationBimap is used to keep pending operations. The left index
   * is for non-unique chunk names, the right index for unique transaction IDs,
   * the relation index reflects the sequence of adding operations, and the info
   * is additional data of the operation.
   */
  typedef boost::bimaps::bimap<boost::bimaps::multiset_of<std::string>,
                               boost::bimaps::set_of<uint32_t>,
                               boost::bimaps::list_of_relation,
                               boost::bimaps::with_info<OperationData> > OperationBimap;

  RemoteChunkStore(std::shared_ptr<BufferedChunkStore> chunk_store,
                   std::shared_ptr<ChunkManager> chunk_manager,
                   std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority);

  ~RemoteChunkStore();

  std::string Get(const ChunkId& name, const Fob& fob);

  int GetAndLock(const ChunkId& name,
                 const ChunkVersion& local_version,
                 const Fob& fob,
                 std::string& content);

  bool Store(const ChunkId& name,
             const NonEmptyString& content,
             const OpFunctor& callback,
             const Fob& fob);

  bool Delete(const ChunkId& name,
              const OpFunctor& callback,
              const Fob& fob);

  bool Modify(const ChunkId& name,
              const NonEmptyString& content,
              const OpFunctor& callback,
              const Fob& fob);

  uintmax_t Size() const;

  uintmax_t Capacity() const;

  uintmax_t NumPendingOps() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return pending_ops_.size();
  }

  bool Empty() const;

  void Clear();

  /// Waits for pending operations, returns false if it times out.
  bool WaitForCompletion();

  /// Print operation statistics to debug log.
  void LogStats();

  /// Sets the time to wait in WaitForCompletion before failing.
  void SetCompletionWaitTimeout(const std::chrono::duration<int>& value) {
    completion_wait_timeout_ = value;
  }
  /// Sets the time to wait in WaitForConflictingOps before failing.
  void SetOperationWaitTimeout(const std::chrono::duration<int>& value) {
    operation_wait_timeout_ = value;
  }

  NumPendingOpsSigPtr sig_num_pending_ops() { return sig_num_pending_ops_; }

//   void StoreOpBackups(std::shared_ptr<boost::asio::deadline_timer> timer,
//                       const std::string& pmid);
//   void DoOpBackups(boost::system::error_code error_code,
//                    const std::string& pmid,
//                    std::shared_ptr<boost::asio::deadline_timer> timer);
//   void RetriveOpBackups();
//   void StopOpBackups();

 protected:
  NumPendingOpsSigPtr sig_num_pending_ops_;

 private:
  enum class WaitResult { kSuccess = 0, kCancelled = -1, kTimeout = -2 };

  RemoteChunkStore(const RemoteChunkStore&);
  RemoteChunkStore& operator=(const RemoteChunkStore&);

  void OnOpResult(const OpType& op_type, const ChunkId& name, const int& result);
  WaitResult WaitForConflictingOps(const ChunkId& name,
                                   const OpType& op_type,
                                   const uint32_t& transaction_id,
                                   std::unique_lock<std::mutex>& lock);
  bool WaitForGetOps(const ChunkId& name,
                     const uint32_t& transaction_id,
                     std::unique_lock<std::mutex>& lock);
  uint32_t EnqueueOp(const ChunkId& name,
                     const OperationData& op_data,
                     std::unique_lock<std::mutex>& lock);
  void ProcessPendingOps(std::unique_lock<std::mutex>& lock);

  std::shared_ptr<BufferedChunkStore> chunk_store_;
  std::shared_ptr<ChunkManager> chunk_manager_;
  std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority_;
  bs2::connection chunk_manager_get_connection_, chunk_manager_store_connection_;
  bs2::connection chunk_manager_modify_connection_, chunk_manager_delete_connection_;
  mutable std::mutex mutex_;
  mutable std::condition_variable cond_var_;
  std::chrono::duration<int> completion_wait_timeout_, operation_wait_timeout_;
  OperationBimap pending_ops_;
  OperationMultiMap failed_ops_;
  std::multiset<ChunkId> waiting_gets_;
  std::set<ChunkId> not_modified_gets_;
  uintmax_t op_count_[5], op_success_count_[5], op_skip_count_[5], op_size_[5];
};

std::shared_ptr<RemoteChunkStore> CreateLocalChunkStore(
    const fs::path& buffered_chunk_store_path,
    const fs::path& local_chunk_manager_path,
    const fs::path& chunk_lock_path,
    boost::asio::io_service& asio_service,  // NOLINT (Dan)
    const bptime::time_duration& delay = bptime::milliseconds(0));

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_REMOTE_CHUNK_STORE_H_
