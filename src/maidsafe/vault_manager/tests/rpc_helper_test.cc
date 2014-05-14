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

#include "maidsafe/vault_manager/rpc_helper.h"

#include <string>

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/test.h"

namespace maidsafe {

namespace vault_manager {

namespace test {


TEST(RpcHelperTest, BEH_SetResponseCallback) {
  AsioService asio_service(1);
  std::function<void(std::string)> call_back;
  std::mutex mutex;
  std::future<std::string> future1{ SetResponseCallback<std::string>(call_back,
                                                                    asio_service.service(),
                                                                    mutex) };

  std::future<std::string> future2{ SetResponseCallback<std::string>(call_back,
                                                                    asio_service.service(),
                                                                    mutex) };
  std::future<std::string> future3{ SetResponseCallback<std::string>(call_back,
                                                                    asio_service.service(),
                                                                    mutex) };


  EXPECT_THROW(future1.get(), maidsafe_error) << "must have failed";
  EXPECT_THROW(future2.get(), maidsafe_error) << "must have failed";
  EXPECT_THROW(future3.get(), maidsafe_error) << "must have failed";
  // TODO (Prakash) extend test

  std::future<std::string> future4{ SetResponseCallback<std::string>(call_back,
                                                                    asio_service.service(),
                                                                    mutex) };
  std::future<std::string> future5{ SetResponseCallback<std::string>(call_back,
                                                                    asio_service.service(),
                                                                    mutex) };
  std::thread t([&]() {
    std::this_thread::sleep_for(std::chrono::seconds(1));
    call_back("result");
  });

  EXPECT_EQ(future4.get(), "result");
  EXPECT_EQ(future5.get(), "result");
  t.join();
}

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe
