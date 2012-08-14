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

#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/client_controller.h"
#include "maidsafe/private/vault_controller.h"
#include "maidsafe/private/vault_manager.h"


namespace maidsafe {

namespace priv {

namespace test {

TEST(VaultManagerTest, BEH_UpdateAndVerify) {
  // Write 1 byte local config file
  WriteFile(fs::path(".") / VaultManager::kConfigFileName(), "~");

  maidsafe::priv::VaultManager vault_manager("");
  for (;;);
}

}  // namespace test

}  // namespace priv

}  // namespace maidsafe
