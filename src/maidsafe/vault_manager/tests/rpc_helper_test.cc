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
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/interprocess_messages.pb.h"
#include "maidsafe/vault_manager/utils.h"


namespace maidsafe {

namespace vault_manager {

namespace test {

TEST(RpcHelperTest, BEH_SetResponseCallback) {
  AsioService asio_service(1);
  asio::io_service& io_service(asio_service.service());
  std::function<void(std::string)> callback;
  std::mutex mutex;
  asymm::PlainText challenge{ RandomString((RandomUint32() % 100) + 100) };

  std::vector<std::future<std::unique_ptr<asymm::PlainText>>> futures;
  for (int i(0); i < 3; ++i)
    futures.emplace_back(SetResponseCallback<std::unique_ptr<asymm::PlainText>>(callback,
                                                                                io_service, mutex));

  for (auto& future : futures)
    EXPECT_THROW(future.get(), maidsafe_error) << "must have failed";

  futures.clear();
  for (int i(0); i < 3; ++i)
    futures.emplace_back(SetResponseCallback<std::unique_ptr<asymm::PlainText>>(callback,
                                                                                io_service, mutex));

  protobuf::Challenge message;
  message.set_plaintext(challenge.string());

  std::thread t([&]() {
    Sleep(std::chrono::milliseconds(100));
    callback(message.SerializeAsString());
  });

  std::unique_ptr<asymm::PlainText> retrieved_challenge;
  for (auto& future : futures) {
    EXPECT_NO_THROW(retrieved_challenge = future.get());
    EXPECT_EQ(challenge, *retrieved_challenge);
  }

  t.join();
}

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe
