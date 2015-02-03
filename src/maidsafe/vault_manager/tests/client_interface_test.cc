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

#include "maidsafe/vault_manager/client_interface.h"

#include <memory>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/process.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_manager.h"
#include "maidsafe/vault_manager/tests/test_utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace test {

TEST(ClientInterfaceTest, BEH_Basic) {
  std::shared_ptr<fs::path> test_env_root_dir{
      maidsafe::test::CreateTestPath("MaidSafe_TestClientInterface")};
  fs::path path_to_vault{process::GetOtherExecutablePath("dummy_vault")};
  SetEnvironment(tcp::Port{8888}, *test_env_root_dir, path_to_vault);

  VaultManager vault_manager;
  static_cast<void>(vault_manager);

  {
    passport::MaidAndSigner maid_and_signer{passport::CreateMaidAndSigner()};
    ClientInterface client_interface{maid_and_signer.first};
    LOG(kVerbose) << "Client stopping.";
  }
}

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe
