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

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_CONFIG_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_CONFIG_H_

#include <cstdint>
#include <string>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace detail {

const std::string kSignatureExtension(".sig");
const std::string kVersionFilename("version");
const std::string kManifestFilename("manifest");
const std::string kGlobalConfigFilename("global-config.dat");
const std::string kBootstrapNodesFilename("bootstrap-global.dat");
const std::string kLifeStuffManagerName("lifestuff_mgr");

#ifdef USE_DUMMY_VAULT
const std::string kVaultName("dummy_vault");

#  ifndef MAIDSAFE_WIN32
std::string GetUserId() {
  return "maidsafe";
}
#  endif

#else
const std::string kVaultName("lifestuff_vault");

#  ifndef MAIDSAFE_WIN32
std::string GetUserId() {
  char user_name[64] = {0};
  int result(getlogin_r(user_name, sizeof(user_name) - 1));
  if (0 != result)
    return "";
  return std::string(user_name);
}
#  endif

#endif

}  // namespace detail

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_CONFIG_H_
