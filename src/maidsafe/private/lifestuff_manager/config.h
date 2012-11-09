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

#include <string>


namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

namespace detail {

const std::string kSignatureExtension(".sig");
const std::string kVersionFilename("version.dat");
const std::string kManifestFilename("manifest.gz");
const std::string kGlobalConfigFilename("global-config.dat");
const std::string kGlobalBootstrapFilename("global-bootstrap.dat");
const std::string kLifeStuffManagerName("lifestuff_mgr");

const std::string kExecutableExtension([]()->std::string {
    if (kTargetPlatform == "Win8" || kTargetPlatform == "Win7" || kTargetPlatform == "Vista")
      return ".exe";
    if (kTargetPlatform == "OSX10.8")
      return "";
    if (kTargetPlatform == "Linux")
      return "";
    return ".unknown";
  }());

const std::string kInstallerExtension([]()->std::string {
    if (kTargetPlatform == "Win8" || kTargetPlatform == "Win7" || kTargetPlatform == "Vista")
      return ".exe";
    if (kTargetPlatform == "OSX10.8")
      return ".dmg";
    if (kTargetPlatform == "Linux")
      return ".rpm";
    return ".unknown";
  }());

const std::string kTargetPlatformAndArchitecture(kTargetPlatform + '_' + kTargetArchitecture);


#ifdef USE_DUMMY_VAULT
const std::string kVaultName("dummy_vault" + kExecutableExtension);

#  ifndef MAIDSAFE_WIN32
std::string GetUserId() {
  return "maidsafe";
}
#  endif

#else
const std::string kVaultName("lifestuff_vault" + kExecutableExtension);

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
