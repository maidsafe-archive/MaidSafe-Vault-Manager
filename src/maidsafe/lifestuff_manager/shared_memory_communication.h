/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_SHARED_MEMORY_COMMUNICATION_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_SHARED_MEMORY_COMMUNICATION_H_

#include <string>

#include "boost/interprocess/mapped_region.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/passport/types.h"

#include "maidsafe/lifestuff_manager/queue_operations.h"

namespace maidsafe {

namespace lifestuff_manager {

namespace detail {

template<typename FobType>
struct is_valid_fob : public std::false_type {};

template<>
struct is_valid_fob<passport::Maid> : public std::true_type {};

template<>
struct is_valid_fob<passport::Pmid> : public std::true_type {};

}  // namespace detail

class LifeStuffManagerAddressGetter {
 public:
  LifeStuffManagerAddressGetter()
      : shared_memory_name_("lifestuff_manager"),
        shared_memory_(boost::interprocess::open_only,
                       shared_memory_name_.c_str(),
                       boost::interprocess::read_write),
        mapped_region_(shared_memory_, boost::interprocess::read_write),
        safe_address_(static_cast<detail::SafeAddress*>(mapped_region_.get_address())) {}

  passport::Maid::Name GetAddress() {
    namespace bip = boost::interprocess;
    bip::scoped_lock<bip::interprocess_mutex> lock(safe_address_->mutex);
    std::string s(safe_address_->address);
    std::cout << "s: " << s.size() << std::endl;
    return passport::Maid::Name(Identity(safe_address_->address));
  }

 private:
  LifeStuffManagerAddressGetter(const LifeStuffManagerAddressGetter& other);
  LifeStuffManagerAddressGetter& operator=(const LifeStuffManagerAddressGetter& other);
  LifeStuffManagerAddressGetter(LifeStuffManagerAddressGetter&& other);
  LifeStuffManagerAddressGetter& operator=(LifeStuffManagerAddressGetter&& other);

  const std::string shared_memory_name_;
  boost::interprocess::shared_memory_object shared_memory_;
  boost::interprocess::mapped_region mapped_region_;
  detail::SafeAddress* safe_address_;
};

class SafeReadOnlySharedMemory {
 public:
  explicit SafeReadOnlySharedMemory(const passport::Maid& maid)
      : maid_(maid),
        shared_memory_name_("lifestuff_manager"),
        shared_memory_(boost::interprocess::create_only,
                       shared_memory_name_.c_str(),
                       boost::interprocess::read_write),
        mapped_region_(nullptr),
        safe_address_(nullptr) {
    shared_memory_.truncate(sizeof(detail::SafeAddress));
    mapped_region_.reset(new boost::interprocess::mapped_region(shared_memory_,
                                                                boost::interprocess::read_write));
    safe_address_ = new (mapped_region_->get_address()) detail::SafeAddress;  // NOLINT (Dan)

    asymm::Signature initial_signature(asymm::Sign(asymm::PlainText(maid.name().value),
                                                   maid.private_key()));
    assert(sizeof(safe_address_->address) == maid.name()->string().size());
    memcpy(safe_address_->address, maid.name()->string().c_str(),
           maid.name()->string().size());
    assert(sizeof(safe_address_->signature) == initial_signature.string().size());
    memcpy(safe_address_->signature, initial_signature.string().c_str(),
           initial_signature.string().size());
    std::cout << "SafeReadOnlySharedMemory instance address: "
              << EncodeToBase32(std::string(safe_address_->address)) << std::endl;
  }

  ~SafeReadOnlySharedMemory() {
    boost::interprocess::shared_memory_object::remove(shared_memory_name_.c_str());
  }

  void ChangeAddress(const Identity& new_address, const asymm::Signature& new_signature) {
    namespace bip = boost::interprocess;
    bip::scoped_lock<bip::interprocess_mutex> lock(safe_address_->mutex);
    Identity current_address(safe_address_->address);
    if (current_address == new_address)
      return;

    if (asymm::CheckSignature(asymm::PlainText(new_address), new_signature, maid_.public_key())) {
      assert(sizeof(safe_address_->address) ==  new_address.string().size());
      memcpy(safe_address_->address, new_address.string().c_str(), new_address.string().size());
      assert(sizeof(safe_address_->signature) == new_signature.string().size());
      memcpy(safe_address_->signature, new_signature.string().c_str(),
             new_signature.string().size());
    } else {
      ThrowError(AsymmErrors::invalid_signature);
    }
  }

 private:
  SafeReadOnlySharedMemory(const SafeReadOnlySharedMemory& other);
  SafeReadOnlySharedMemory& operator=(const SafeReadOnlySharedMemory& other);
  SafeReadOnlySharedMemory(SafeReadOnlySharedMemory&& other);
  SafeReadOnlySharedMemory& operator=(SafeReadOnlySharedMemory&& other);

  passport::Maid maid_;
  const std::string shared_memory_name_;
  boost::interprocess::shared_memory_object shared_memory_;
  std::unique_ptr<boost::interprocess::mapped_region> mapped_region_;
  detail::SafeAddress* safe_address_;
};

// This class contains raw pointers that are managed by the boost IPC library. Changing any
// of them to smart pointers results in a double free. The message queue construction syntax
// is what is used to give the object a place to be constructed in memory. Using that same
// address on different processes is what allows the communication.
template <typename FobType, typename CreationTag>
class SharedMemoryCommunication {
 public:
  SharedMemoryCommunication(const typename FobType::Name& shared_memory_name,
                            std::function<void(std::string)> message_notifier)
      : shared_memory_name_(shared_memory_name),
        shared_memory_(nullptr),
        mapped_region_(nullptr),
        message_queue_(nullptr),
        message_notifier_(message_notifier),
        receive_flag_(true),
        receive_future_() {
    static_assert(detail::is_valid_fob<FobType>::value,
                  "Type of identifier name must be either MAID or PMID");
    assert(message_notifier_ && "A non-null function must be provided.");
    detail::DecideDeletion<CreationTag>()(shared_memory_name_->string());
    shared_memory_.reset(new boost::interprocess::shared_memory_object(
                             CreationTag(),
                             shared_memory_name_->string().c_str(),
                             boost::interprocess::read_write));
    detail::DecideTruncate<CreationTag>()(*shared_memory_);

    mapped_region_.reset(new boost::interprocess::mapped_region(*shared_memory_,
                                                                boost::interprocess::read_write));
    detail::CreateQueue<CreationTag>()(message_queue_, *mapped_region_);
    StartCheckingReceivingQueue();
  }

  bool PushMessage(const std::string& message) {
    if (message.size() > size_t(detail::IpcBidirectionalQueue::kMessageSize))
      return false;
    return detail::PushMessageToQueue<CreationTag>().Push(std::ref(message_queue_), message);
  }

  ~SharedMemoryCommunication() {
    detail::DecideDeletion<CreationTag>()(shared_memory_name_->string());
    receive_flag_.store(false);
    receive_future_.get();
  }

 private:
  SharedMemoryCommunication(const SharedMemoryCommunication& other);
  SharedMemoryCommunication& operator=(const SafeReadOnlySharedMemory& other);
  SharedMemoryCommunication(SharedMemoryCommunication&& other);
  SharedMemoryCommunication& operator=(SharedMemoryCommunication&& other);

  typename FobType::Name shared_memory_name_;
  std::unique_ptr<boost::interprocess::shared_memory_object> shared_memory_;
  std::unique_ptr<boost::interprocess::mapped_region> mapped_region_;
  detail::IpcBidirectionalQueue* message_queue_;
  std::function<void(std::string)> message_notifier_;
  std::atomic<bool> receive_flag_;
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

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_SHARED_MEMORY_COMMUNICATION_H_
