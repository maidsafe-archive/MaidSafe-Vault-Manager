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

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_TESTS_TEST_UTILS_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_TESTS_TEST_UTILS_H_

#include <string>


namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace test {

int GetNumRunningProcesses(const std::string& process_name);

}  // namespace test

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_TESTS_TEST_UTILS_H_
