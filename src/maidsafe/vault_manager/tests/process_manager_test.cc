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

#include "maidsafe/vault_manager/process_manager.h"

#include <thread>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/process.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/config.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/tests/test_utils.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace test {

TEST(ProcessManagerTest, BEH_Constructor) {
  fs::path path_to_vault{process::GetOtherExecutablePath("dummy_vault")};
  std::unique_ptr<AsioService> asio_service{maidsafe::make_unique<AsioService>(1)};
  std::shared_ptr<ProcessManager> process_manager{
      ProcessManager::MakeShared(asio_service->service(), path_to_vault, tcp::Port{7777})};
  process_manager->StopAll();
  LOG(kInfo) << "Destroying asio...";
  asio_service.reset();
}

}  // namespace test

}  // namespace vault_manager

}  // namespace maidsafe
