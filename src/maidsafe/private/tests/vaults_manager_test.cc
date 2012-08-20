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

#include "maidsafe/common/log.h"
#include "maidsafe/common/return_codes.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "boost/date_time/posix_time/posix_time_duration.hpp"

#include "maidsafe/private/client_controller.h"
#include "maidsafe/private/vault_controller.h"
#include "maidsafe/private/vaults_manager.h"


namespace bptime = boost::posix_time;

namespace maidsafe {

namespace priv {

namespace test {

TEST(VaultsManagerTest, BEH_StartStop) {
  // Write 1 byte local config file
  WriteFile(fs::path(".") / VaultsManager::kConfigFileName(), "~");

  maidsafe::priv::VaultsManager vaults_manager;
  maidsafe::priv::ClientController client_controller;

  int max_seconds = VaultsManager::kMaxUpdateInterval().total_seconds();
  EXPECT_FALSE(client_controller.SetUpdateInterval(bptime::seconds(max_seconds + 1)));
  EXPECT_TRUE(client_controller.SetUpdateInterval(bptime::seconds(max_seconds)));
  int min_seconds = VaultsManager::kMinUpdateInterval().total_seconds();
  EXPECT_TRUE(client_controller.SetUpdateInterval(bptime::seconds(min_seconds)));
  EXPECT_FALSE(client_controller.SetUpdateInterval(bptime::seconds(min_seconds - 1)));

  asymm::Keys keys;
  ASSERT_EQ(kSuccess, rsa::GenerateKeyPair(&keys));
  EXPECT_TRUE(client_controller.StartVault(keys, "F"));

  Sleep(boost::posix_time::seconds(10));
}

}  // namespace test

}  // namespace priv

}  // namespace maidsafe
