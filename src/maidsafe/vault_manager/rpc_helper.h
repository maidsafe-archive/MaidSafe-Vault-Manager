/*  Copyright 2014 MaidSafe.net limited

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

#ifndef MAIDSAFE_VAULT_MANAGER_RPC_HELPER_H_
#define MAIDSAFE_VAULT_MANAGER_RPC_HELPER_H_

#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <string>

#include "asio/error.hpp"
#include "asio/io_service.hpp"
#include "asio/steady_timer.hpp"
#include "boost/exception/diagnostic_information.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/utils.h"

namespace maidsafe {

namespace vault_manager {

namespace detail {

template <typename ResultType>
struct PromiseAndTimer {
  PromiseAndTimer(asio::io_service& io_service,
                  const std::chrono::steady_clock::duration& timeout = kRpcTimeout);

  void ParseAndSetValue(const std::string& message);
  void SetValue(ResultType&& result);  // Check
  void SetException(std::exception_ptr exception);
  void SetException(maidsafe_error error);
  void SetException(std::error_code error_code);

  std::promise<ResultType> promise;
  Timer timer;
  std::once_flag once_flag;
};

template <typename ResultType>
PromiseAndTimer<ResultType>::PromiseAndTimer(asio::io_service& io_service,
                                             const std::chrono::steady_clock::duration& timeout)
    : promise(), timer(io_service, timeout), once_flag() {}

template <typename ResultType>
void PromiseAndTimer<ResultType>::ParseAndSetValue(const std::string& message) {
  ResultType result(Parse<ResultType>(message));
  std::call_once(once_flag, [&] { this->promise.set_value(std::move(result)); });
}

template <typename ResultType>
void PromiseAndTimer<ResultType>::SetValue(ResultType&& result) {
  std::call_once(once_flag, [&] { this->promise.set_value(std::move(result)); });
}

template <typename ResultType>
void PromiseAndTimer<ResultType>::SetException(std::exception_ptr exception) {
  std::call_once(once_flag, [&] { this->promise.set_exception(exception); });
}

template <typename ResultType>
void PromiseAndTimer<ResultType>::SetException(maidsafe_error error) {
  std::call_once(once_flag, [&] { this->promise.set_exception(std::make_exception_ptr(error)); });
}

template <typename ResultType>
void PromiseAndTimer<ResultType>::SetException(std::error_code error_code) {
  std::call_once(once_flag, [&] {
    this->promise.set_exception(std::make_exception_ptr(std::system_error(error_code)));
  });
}

}  // namespace detail

template <typename ResultType>
std::future<ResultType> SetResponseCallback(std::function<void(std::string)>& callback,
                                            asio::io_service& io_service, std::mutex& mutex) {
  auto promise_and_timer = std::make_shared<detail::PromiseAndTimer<ResultType>>(io_service);
  {
    std::lock_guard<std::mutex> lock{mutex};
    auto callback_copy(callback);
    callback = [=](std::string message) {
      if (callback_copy)
        callback_copy(message);
      try {
        promise_and_timer->ParseAndSetValue(message);
      } catch (const std::exception& e) {
        LOG(kError) << boost::diagnostic_information(e);
        promise_and_timer->SetException(std::current_exception());
      }
      promise_and_timer->timer.cancel();
    };
  }
  promise_and_timer->timer.async_wait([=, &callback, &mutex](const std::error_code& ec) {
    if (ec && ec == asio::error::operation_aborted) {
      LOG(kVerbose) << "Timer cancelled";
      return;
    }
    LOG(kVerbose) << "Timer expired - i.e. timed out";
    std::lock_guard<std::mutex> lock{mutex};
    if (callback)
      callback = nullptr;
    if (ec)
      promise_and_timer->SetException(ec);
    else
      promise_and_timer->SetException(MakeError(VaultManagerErrors::timed_out));
  });
  return promise_and_timer->promise.get_future();
}

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_RPC_HELPER_H_
