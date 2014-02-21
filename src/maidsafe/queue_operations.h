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

#ifndef MAIDSAFE_CLIENT_MANAGER_QUEUE_OPERATIONS_H_
#define MAIDSAFE_CLIENT_MANAGER_QUEUE_OPERATIONS_H_

#include <atomic>
#include <string>

#include "boost/interprocess/creation_tags.hpp"
#include "boost/interprocess/shared_memory_object.hpp"
#include "boost/interprocess/sync/interprocess_mutex.hpp"
#include "boost/interprocess/sync/interprocess_condition.hpp"
#include "boost/interprocess/sync/scoped_lock.hpp"

#include "maidsafe/client_manager/queue_struct.h"

namespace maidsafe {

namespace client_manager {

namespace detail {

namespace bip = boost::interprocess;

typedef bip::create_only_t SharedMemoryCreateOnly;
typedef bip::open_only_t SharedMemoryOpenOnly;

inline boost::posix_time::ptime Until(const boost::posix_time::time_duration& duration) {
  return boost::posix_time::microsec_clock::universal_time() + duration;
}

// decide whether to truncate the memory block based on who is the owner
template <typename CreationTag>
struct DecideTruncate {};

template <>
struct DecideTruncate<SharedMemoryCreateOnly> {
  void operator()(bip::shared_memory_object& shared_memory) {
    shared_memory.truncate(sizeof(IpcBidirectionalQueue));
  }
};

template <>
struct DecideTruncate<SharedMemoryOpenOnly> {
  void operator()(bip::shared_memory_object&) {}
};

// decide whether to allocate the memory of the queue or jsut get a pointer to it
template <typename CreationTag>
struct CreateQueue {};

template <>
struct CreateQueue<SharedMemoryCreateOnly> {
  void operator()(IpcBidirectionalQueue*& queue,
                  boost::interprocess::mapped_region& mapped_region) {
    queue = new (mapped_region.get_address()) IpcBidirectionalQueue;  // NOLINT (Dan)
  }
};

template <>
struct CreateQueue<SharedMemoryOpenOnly> {
  void operator()(IpcBidirectionalQueue*& queue,
                  boost::interprocess::mapped_region& mapped_region) {
    queue = static_cast<IpcBidirectionalQueue*>(mapped_region.get_address());
  }
};

// decide whether to delete the shared memory allocated based on who is the owner
template <typename CreationTag>
struct DecideDeletion {};

template <>
struct DecideDeletion<SharedMemoryCreateOnly> {
  void operator()(const std::string& name) { bip::shared_memory_object::remove(name.c_str()); }
};

template <>
struct DecideDeletion<SharedMemoryOpenOnly> {
  void operator()(const std::string&) {}
};

// Decide which mutex to use and which conditionals to trigger when pushing to the queue based on
// parent/child process
template <typename CreationTag>
struct PushMessageToQueue {};

template <>
struct PushMessageToQueue<SharedMemoryCreateOnly> {
  bool Push(IpcBidirectionalQueue*& queue, const std::string& message) {
    bip::scoped_lock<bip::interprocess_mutex> lock(queue->pwcr_mutex);
    if (!queue->parent_write.timed_wait(
             lock, Until(boost::posix_time::milliseconds(10000)),
                       [&queue]()->bool { return !queue->message_from_parent; })) {
      std::cout << "timed out parent write 3" << std::endl;
      return false;
    }

    // Add the message to the char array
    memcpy(queue->parent_message, message.c_str(), message.size());

    // Notify the other process that the buffer is full
    queue->message_from_parent = true;
    queue->child_read.notify_one();
    return true;
  }
};

template <>
struct PushMessageToQueue<SharedMemoryOpenOnly> {
  bool Push(IpcBidirectionalQueue*& queue, const std::string& message) {
    bip::scoped_lock<bip::interprocess_mutex> lock(queue->cwpr_mutex);
    if (!queue->child_write.timed_wait(
             lock, Until(boost::posix_time::milliseconds(10000)),
                       [&queue]()->bool { return !queue->message_from_child; })) {
      std::cout << "timed out child write 3" << std::endl;
      return false;
    }

    memcpy(queue->child_message, message.c_str(), message.size());
    // Notify the other process that the buffer is full
    queue->message_from_child = true;
    queue->parent_read.notify_one();
    return true;
  }
};

// Decide which mutex to use and which conditionals to trigger when popping from the queue based on
// parent/child process
template <typename CreationTag>
struct RunRecevingThread {};

template <>
struct RunRecevingThread<SharedMemoryCreateOnly> {
  std::future<void> GetThreadFuture(IpcBidirectionalQueue*& queue, std::atomic<bool>& receive_flag,
                                    const std::function<void(std::string)>& message_notifier) {
    return std::async(std::launch::async, [&queue, &receive_flag, &message_notifier]() {
      while (receive_flag.load()) {
        bip::scoped_lock<bip::interprocess_mutex> lock(queue->cwpr_mutex);
        if (!queue->parent_read.timed_wait(
                 lock, Until(boost::posix_time::milliseconds(100)),
                           [&queue]()->bool { return queue->message_from_child; }))
          continue;

        // Notify of message
        message_notifier(std::string(queue->child_message));

        // Notify the other process that the buffer is empty
        queue->message_from_child = false;
        queue->child_write.notify_one();
      }
    });
  }
};

template <>
struct RunRecevingThread<SharedMemoryOpenOnly> {
  std::future<void> GetThreadFuture(IpcBidirectionalQueue*& queue, std::atomic<bool>& receive_flag,
                                    const std::function<void(std::string)>& message_notifier) {
    return std::async(std::launch::async, [&queue, &receive_flag, &message_notifier]() {
      while (receive_flag.load()) {
        bip::scoped_lock<bip::interprocess_mutex> lock(queue->pwcr_mutex);
        if (!queue->child_read.timed_wait(
                 lock, Until(boost::posix_time::milliseconds(100)),
                           [&queue]()->bool { return queue->message_from_parent; }))
          continue;

        // Notify of message
        message_notifier(std::string(queue->parent_message));

        // Notify the other process that the buffer is empty
        queue->message_from_parent = false;
        queue->parent_write.notify_one();
      }
    });
  }
};

}  // namespace detail

}  // namespace client_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_CLIENT_MANAGER_QUEUE_OPERATIONS_H_
