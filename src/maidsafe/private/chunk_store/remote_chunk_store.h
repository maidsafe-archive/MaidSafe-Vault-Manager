/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  remote_chunk_store.h
 * @brief Class implementing %ChunkStore wrapper for %ChunkManager.
 * @date  2011-05-18
 */

#ifndef MAIDSAFE_PRIVATE_CHUNK_STORE_REMOTE_CHUNK_STORE_H_
#define MAIDSAFE_PRIVATE_CHUNK_STORE_REMOTE_CHUNK_STORE_H_

#include <functional>
#include <list>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <utility>

#include "boost/bimap.hpp"
// #include "boost/serialization/access.hpp"
#include "boost/thread/condition_variable.hpp"
#include "boost/thread/locks.hpp"
#include "boost/thread/mutex.hpp"

#include "maidsafe/private/chunk_actions/chunk_action_authority.h"
#include "maidsafe/private/chunk_store/buffered_chunk_store.h"
#include "maidsafe/private/chunk_store/chunk_manager.h"

#include "maidsafe/private/version.h"
#if MAIDSAFE_PRIVATE_VERSION != 300
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif

namespace maidsafe {

namespace priv {

namespace chunk_actions { class ChunkActionAuthority; }

namespace chunk_store {

class BufferedChunkStore;

class RemoteChunkStore {
 public:
  enum OperationType {
    kOpGet = 0,
    kOpStore = 1,
    kOpModify = 2,
    kOpDelete = 3
  };

  static const std::string kOpName[];  // see implementation

  struct ValidationData {
    ValidationData(const asymm::Keys &key_pair_in,
                   const std::string &ownership_proof_in)
        : key_pair(key_pair_in),
          ownership_proof(ownership_proof_in) {}
    ValidationData() : key_pair(), ownership_proof() {}
    asymm::Keys key_pair;
    std::string ownership_proof;
  };

  struct OperationData {
    OperationData()
        : op_type(),
          owner_key_id(),
          owner_public_key(),
          ownership_proof(),
          content(),
          get_cb() {}
    explicit OperationData(const OperationType &op_type)
        : op_type(op_type),
          owner_key_id(),
          owner_public_key(),
          ownership_proof(),
          content(),
          get_cb() {}
    OperationData(const OperationType &op_type,
                  const ValidationData &validation_data)
        : op_type(op_type),
          owner_key_id(validation_data.key_pair.identity),
          owner_public_key(validation_data.key_pair.public_key),
          ownership_proof(validation_data.ownership_proof),
          content(),
          get_cb() {}
    OperationType op_type;
    asymm::Identity owner_key_id;
    asymm::PublicKey owner_public_key;
    std::string ownership_proof;
    std::string content;
    GetFunctor get_cb;
  };

  typedef std::map<std::string, OperationData> OperationMap;
  typedef std::multimap<std::string, OperationData> OperationMultiMap;
  /**
   * The OperationBimap is used to keep pending operations. The left index
   * is for non-unique chunk names, the right index for unique transaction IDs,
   * the relation index reflects the sequence of adding operations, and the info
   * is additional data of the operation.
   */
  typedef boost::bimaps::bimap<boost::bimaps::multiset_of<std::string>,
                               boost::bimaps::set_of<uint32_t>,
                               boost::bimaps::list_of_relation,
                               boost::bimaps::with_info<OperationData> >
      OperationBimap;
  typedef std::function<void(bool)> OperationFunctor;  // NOLINT
  typedef std::function<void(std::string)> GetFunctor;  // NOLINT

  RemoteChunkStore(
      std::shared_ptr<BufferedChunkStore> chunk_store,
      std::shared_ptr<ChunkManager> chunk_manager,
      std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority);  // NOLINT (Dan)

  ~RemoteChunkStore();

  std::string Get(
      const std::string &name,
      const ValidationData &validation_data = ValidationData()) const;

  bool Get(const std::string &name,
           const fs::path &sink_file_name,
           const ValidationData &validation_data = ValidationData()) const;

  void Get(const std::string &name,
           const ValidationData &validation_data,
           GetFunctor callback);

  bool Store(const std::string &name,
             const std::string &content,
             const ValidationData &validation_data = ValidationData());

  bool Store(const std::string &name,
             const fs::path &source_file_name,
             bool delete_source_file,
             const ValidationData &validation_data = ValidationData());

  bool Delete(const std::string &name,
              const ValidationData &validation_data = ValidationData());

  bool Modify(const std::string &name,
              const std::string &content,
              const ValidationData &validation_data = ValidationData());

  bool Modify(const std::string &name,
              const fs::path &source_file_name,
              bool delete_source_file,
              const ValidationData &validation_data = ValidationData());

  bool MoveTo(const std::string&, ChunkStore*) {
    return false;
  }

  bool Has(const std::string &name) const { return chunk_store_->Has(name); }

  std::uintmax_t Size(const std::string &name) const {
    return chunk_store_->Size(name);
  }

  std::uintmax_t Size() const {
    // TODO(Steve) get from account
    return 0;  // chunk_store_->Size();
  }

  std::uintmax_t Capacity() const {
    // TODO(Steve) get from account
    return 0;  // chunk_store_->Capacity();
  }

  bool Vacant(const std::uintmax_t&) const {
    return true;  // return chunk_store_->Vacant(size);
  }

  std::uintmax_t Count(const std::string &name) const {
    return chunk_store_->Count(name);
  }

  std::uintmax_t Count() const {
    return 0;  // return chunk_store_->Count();
  }

  bool Empty() const {
    return chunk_store_->Empty();
  }

  void Clear() {
    chunk_store_->Clear();
  }

  /// Waits for pending operations, returns false if it times out.
  bool WaitForCompletion();

  /// Sets the maximum number of operations to be processed in parallel.
  void SetMaxActiveOps(int max_active_ops) {
    max_active_ops_ = max_active_ops;
    if (max_active_ops_ < 1)
      max_active_ops_ = 1;
  }

  ChunkManager::ChunkStoredSigPtr sig_chunk_stored() {
    return sig_chunk_stored_;
  }
  ChunkManager::ChunkModifiedSigPtr sig_chunk_modified() {
    return sig_chunk_modified_;
  }
  ChunkManager::ChunkDeletedSigPtr sig_chunk_deleted() {
    return sig_chunk_deleted_;
  }

//   friend class boost::serialization::access;
//   template<class Archive>
//   void serialize(Archive &archive, const unsigned int version);  // NOLINT
//
//   void StoreOpBackups(std::shared_ptr<boost::asio::deadline_timer> timer,
//                       const std::string &pmid);
//   void DoOpBackups(boost::system::error_code error_code,
//                    const std::string &pmid,
//                    std::shared_ptr<boost::asio::deadline_timer> timer);
//   void RetriveOpBackups();
//   void StopOpBackups();

 private:
  RemoteChunkStore(const RemoteChunkStore&);
  RemoteChunkStore& operator=(const RemoteChunkStore&);

  void SetCapacity(const std::uintmax_t&) {}

  void OnOpResult(const OperationType &op_type,
                  const std::string &name,
                  const int &result);
  std::string DoGet(const std::string &name,
                    const ValidationData &validation_data) const;
  int WaitForConflictingOps(const std::string &name,
                            const OperationType &op_type,
                            const uint32_t &transaction_id,
                            boost::mutex::scoped_lock *lock);
  uint32_t EnqueueOp(const std::string &name,
                     const OperationData &op_data);
  void ProcessPendingOps(boost::mutex::scoped_lock *lock);

  ChunkManager::ChunkStoredSigPtr sig_chunk_stored_;
  ChunkManager::ChunkModifiedSigPtr sig_chunk_modified_;
  ChunkManager::ChunkDeletedSigPtr sig_chunk_deleted_;
  std::shared_ptr<BufferedChunkStore> chunk_store_;
  std::shared_ptr<ChunkManager> chunk_manager_;
  std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority_;
  bs2::connection cm_get_conn_,
                  cm_store_conn_,
                  cm_modify_conn_,
                  cm_delete_conn_;
  mutable boost::mutex mutex_;
  mutable boost::condition_variable cond_var_;
  mutable int max_active_ops_;
  mutable OperationMap active_ops_;
  mutable OperationBimap pending_ops_;
  mutable OperationMultiMap failed_ops_;
  mutable std::uintmax_t op_count_[4], op_success_count_[4], op_size_[4];
};

std::shared_ptr<RemoteChunkStore> CreateLocalChunkStore(
    const fs::path &base_dir,
    boost::asio::io_service &asio_service);  // NOLINT (Dan)

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_REMOTE_CHUNK_STORE_H_
