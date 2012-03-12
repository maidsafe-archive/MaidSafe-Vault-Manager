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
#include <memory>
#include <set>
#include <string>
#include <utility>

#include "boost/multi_index_container.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/composite_key.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/mem_fun.hpp"

#include "boost/thread/condition_variable.hpp"
#include "boost/thread/locks.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/thread/shared_mutex.hpp"

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
          content() {}
    explicit OperationData(const OperationType &op_type)
        : op_type(op_type),
          owner_key_id(),
          owner_public_key(),
          ownership_proof(),
          content() {}
    OperationData(const OperationType &op_type,
                  const ValidationData &validation_data)
        : op_type(op_type),
          owner_key_id(validation_data.key_pair.identity),
          owner_public_key(validation_data.key_pair.public_key),
          ownership_proof(validation_data.ownership_proof),
          content() {}
    OperationType op_type;
    asymm::Identity owner_key_id;
    asymm::PublicKey owner_public_key;
    std::string ownership_proof;
    std::string content;
  };

  typedef std::pair<std::string, OperationData> Operation;

  RemoteChunkStore(
      std::shared_ptr<BufferedChunkStore> chunk_store,
      std::shared_ptr<ChunkManager> chunk_manager,
      std::shared_ptr<chunk_actions::ChunkActionAuthority> chunk_action_authority);  // NOLINT (Dan)

  ~RemoteChunkStore();
  void Init();
  std::string Get(
      const std::string &name,
      const ValidationData &validation_data = ValidationData()) const;

  bool Get(const std::string &name,
           const fs::path &sink_file_name,
           const ValidationData &validation_data = ValidationData()) const;

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
  void EnqueueModOp(const std::string &name,
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
  mutable int max_active_ops_, active_ops_count_;
  mutable std::set<std::string> active_get_ops_, active_mod_ops_;
  mutable std::multiset<std::string> waiting_getters_;
  mutable std::list<Operation> pending_mod_ops_, failed_hashable_ops_;
  mutable std::set<std::string> failed_non_hashable_store_ops_;
  mutable std::uintmax_t get_op_count_,
                         store_op_count_,
                         modify_op_count_,
                         delete_op_count_;
  std::uintmax_t get_success_count_,
                 store_success_count_,
                 modify_success_count_,
                 delete_success_count_;
  std::uintmax_t get_total_size_, store_total_size_, modify_total_size_;
};

/*

namespace op_archiving {

int Serialize(const maidsafe::pd::RemoteChunkStore &remote_chunk_store,
              std::stringstream *output_stream);
int Deserialize(std::stringstream *input_stream,
                maidsafe::pd::RemoteChunkStore &remote_chunk_store);

}  // namespace op_archiving

*/

std::shared_ptr<RemoteChunkStore> CreateLocalChunkStore(
    const fs::path &base_dir,
    boost::asio::io_service &asio_service,  // NOLINT (Dan)
    const boost::posix_time::time_duration &millisecs =
        boost::posix_time::milliseconds(0));

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_STORE_REMOTE_CHUNK_STORE_H_
