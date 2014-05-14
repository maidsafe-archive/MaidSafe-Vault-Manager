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

#include <boost/exception/diagnostic_information.hpp>

#include <future>
#include <memory>
#include <string>


#include "boost/asio/steady_timer.hpp"
#include "boost/asio/error.hpp"


#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/utils.h"

namespace maidsafe {

namespace vault_manager {

namespace detail {

template <typename ResultType>
struct PromiseAndTimer {
  explicit PromiseAndTimer(boost::asio::io_service& io_service);
  void ParseAndSetValue(const std::string& message);
  void SetException(std::exception_ptr exception);

  std::promise<ResultType> promise;
  Timer timer;
  std::once_flag once_flag;
};

template <typename ResultType>
PromiseAndTimer<ResultType>::PromiseAndTimer(boost::asio::io_service& io_service)
    : promise(),
      timer(io_service, kRpcTimeout),
      once_flag() {}

template <typename ResultType>
void PromiseAndTimer<ResultType>::ParseAndSetValue(const std::string& message) {
  ResultType result(detail::Parse<ResultType>(message));
  std::call_once(once_flag, [&]() { promise.set_value(result); });
}

template <typename ResultType>
void PromiseAndTimer<ResultType>::SetException(std::exception_ptr exception) {
  std::call_once(once_flag, [&]() { promise.set_exception(exception); });
}

}  // namespace detail

template <typename ResultType>
std::future<ResultType> SetResponseCallback(std::function<void(std::string)>& call_back,
                                            boost::asio::io_service& io_service,
                                            std::mutex& mutex) {
  auto promise_and_timer = std::make_shared<detail::PromiseAndTimer<ResultType>>(io_service);
  {
    std::lock_guard<std::mutex> lock{ mutex };
    if (call_back) {
      auto call_back_copy(call_back);
      call_back = [=](std::string message) {
        LOG(kVerbose) << "Invoking chained functor";
        call_back_copy(message);
        try {
          promise_and_timer->ParseAndSetValue(message);
        }
        catch (std::exception& e) {
          LOG(kError) << boost::diagnostic_information(e);
          promise_and_timer->SetException(std::current_exception());
        }
        promise_and_timer->timer.cancel();
      };
    } else {
      call_back = [=](std::string message) {
        LOG(kVerbose) << "Invoking functor";
        promise_and_timer->ParseAndSetValue(message);
        promise_and_timer->timer.cancel();
      };
    }
  }

  promise_and_timer->timer.async_wait([=, &call_back, &mutex](const boost::system::error_code&
                                                                error_code) {
    if (error_code && error_code == boost::asio::error::operation_aborted) {
      LOG(kVerbose) << "Timer cancelled";
    } else {
      LOG(kVerbose) << "Timer expired - i.e. timeout";
      std::lock_guard<std::mutex> lock{ mutex };
      if (call_back) {
        call_back = nullptr;
      }
      promise_and_timer->SetException(std::make_exception_ptr((MakeError(RoutingErrors::timed_out))));  // FIXME
    }
  });
  return promise_and_timer->promise.get_future();
}

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_RPC_HELPER_H_
