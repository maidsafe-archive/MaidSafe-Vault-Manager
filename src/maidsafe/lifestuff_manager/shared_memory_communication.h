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

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_SHARED_MEMORY_COMMUNICATIONS_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_SHARED_MEMORY_COMMUNICATIONS_H_

#include "boost/interprocess/mapped_region.hpp"

#include "maidsafe/passport/types.h"

#include "maidsafe/lifestuff_manager/queue_operations.h"

namespace maidsafe {

namespace lifestuff_manager {

namespace {

template<typename FobType>
struct is_valid_fob : public std::false_type {};

template<>
struct is_valid_fob<passport::Maid> : public std::true_type {};

template<>
struct is_valid_fob<passport::Pmid> : public std::true_type {};

}

// This class contains raw pointers that are managed by the boost IPC library. Changing any
// of them to smart pointers results in a double free. The message queue construction syntax
// is what is used to give the object a place to be constructed in memory. Using that same
// address on different processes is what allows the communication.
template <typename FobType, typename CreationTag>
class SharedMemoryCommunication {
 public:
  SharedMemoryCommunication(const typename FobType::name_type& shared_memory_name,
                            std::function<void(std::string)> message_notifier)
      : shared_memory_name_(shared_memory_name),
        shared_memory_(nullptr),
        mapped_region_(nullptr),
        message_queue_(nullptr),
        message_notifier_(message_notifier),
        receive_flag_(true),
        receive_future_() {
    static_assert(is_valid_fob<FobType>::value,
                  "Type of identifier name must be either MAID or PMID");
    assert(message_notifier_ && "A non-null function must be provided.");
    detail::DecideDeletion<CreationTag>()(shared_memory_name_->string());
    shared_memory_.reset(new boost::interprocess::shared_memory_object(
                             typename CreationTag::value_type(),
                             shared_memory_name_->string().c_str(),
                             boost::interprocess::read_write));
    detail::DecideTruncate<CreationTag>()(*shared_memory_);

    mapped_region_.reset(new boost::interprocess::mapped_region(*shared_memory_,
                                                                boost::interprocess::read_write));
    message_queue_ = new (mapped_region_->get_address()) detail::IpcBidirectionalQueue;
    StartCheckingReceivingQueue();
  }

  bool PushMessage(const std::string& message) {
    return detail::PushMessageToQueue<CreationTag>().Push(std::ref(message_queue_), message);
  }

  ~SharedMemoryCommunication() {
    detail::DecideDeletion<CreationTag>()(shared_memory_name_->string());
    receive_flag_.store(false);
    receive_future_.get();
  }

 private:
  typename FobType::name_type shared_memory_name_;
  std::unique_ptr<boost::interprocess::shared_memory_object> shared_memory_;
  std::unique_ptr<boost::interprocess::mapped_region> mapped_region_;
  detail::IpcBidirectionalQueue* message_queue_;
  std::function<void(std::string)> message_notifier_;
  std::atomic_bool receive_flag_;
  std::future<void> receive_future_;

  void StartCheckingReceivingQueue() {
    receive_future_ = detail::RunRecevingThread<CreationTag>().GetThreadFuture(
                          std::ref(message_queue_),
                          std::ref(receive_flag_),
                          std::ref(message_notifier_));
  }
};

typedef SharedMemoryCommunication<passport::Maid, detail::SharedMemoryCreateOnly>
        MaidSharedMemoryOwner;
typedef SharedMemoryCommunication<passport::Pmid, detail::SharedMemoryCreateOnly>
        PmidSharedMemoryOwner;
typedef SharedMemoryCommunication<passport::Maid, detail::SharedMemoryOpenOnly>
        MaidSharedMemoryUser;
typedef SharedMemoryCommunication<passport::Pmid, detail::SharedMemoryOpenOnly>
        PmidSharedMemoryUser;

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_SHARED_MEMORY_COMMUNICATIONS_H_
