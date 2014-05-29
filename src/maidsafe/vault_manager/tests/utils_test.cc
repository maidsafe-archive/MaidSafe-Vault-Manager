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

#include "maidsafe/vault_manager/utils.h"

#include <utility>

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/interprocess_messages.pb.h"

namespace maidsafe {

namespace vault_manager {

namespace test {

TEST(UtilsTest, BEH_ParseProto) {
  EXPECT_THROW(ParseProto<protobuf::Challenge>(""), common_error);

  protobuf::Challenge challenge;
  const std::string kPlainText(RandomString(100));
  challenge.set_plaintext(kPlainText);
  EXPECT_EQ(kPlainText, ParseProto<protobuf::Challenge>(challenge.SerializeAsString()).plaintext());
}

TEST(UtilsTest, BEH_WrapAndUnwrapMessage) {
  protobuf::Challenge challenge;
  const std::string kPlainText(RandomString(100));
  challenge.set_plaintext(kPlainText);

  MessageAndType message_and_type{ std::make_pair(challenge.SerializeAsString(),
                                                  MessageType::kChallenge) };
  std::string serialised_message;
  EXPECT_NO_THROW(serialised_message = WrapMessage(message_and_type));
  EXPECT_FALSE(serialised_message.empty());

  EXPECT_THROW(UnwrapMessage(""), common_error);
  MessageAndType recovered;
  EXPECT_NO_THROW(recovered = UnwrapMessage(serialised_message));
  EXPECT_EQ(message_and_type, recovered);
  EXPECT_EQ(kPlainText, ParseProto<protobuf::Challenge>(message_and_type.first).plaintext());
}

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe
