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

#include "maidsafe/common/config.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"


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

inline asymm::PublicKey kMaidSafePublicKey() {
  static auto const decoded_key = asymm::DecodeKey(asymm::EncodedPublicKey(DecodeFromHex("308201080282010100e97d80923586b7ac2c72b8087598af9bd054249879b8d99c249af05ae4338dcd969c440a39a79d8caba34a7bc5571e92557c1ede11d48ba34dc464b7f7f358092d391622a2a20c183d6f2969827e537e6dd650f7f17cfa9ca8b3e90b86212e0718855468286d353d0279e6cbdc70b338fa56362b15c7534e2ee1ff6271c8a98b09f7bab16c47576826aefa2485720c0bf30c28deb5d5eb583fdfb3b4182f4ba83b7b004d414bf7ae4c54402ed86064096ba2cec02fcaf3368c9b04700e5e7a55f2d16286ad890d7c39395a04ccd27f7302ff55ba5eea4f5ae9d81371db9bb32dcbecca9a1f96c6a58bd9b63e2bfcf89ecaf1b2b0d29e798892968d0f0057e177020111")));  // NOLINT
  return decoded_key;
}

const std::string kDownloadManagerLocation("downloads");
// TODO(Fraser#5#): 2012-11-10 - BEFORE_RELEASE - Change to actual value
const std::string kDownloadManagerSite("109.228.30.58");
const std::string kDownloadManagerProtocol("http");


#ifdef USE_DUMMY_VAULT
const std::string kVaultName("dummy_vault" + kExecutableExtension);

#  ifndef MAIDSAFE_WIN32
inline std::string GetUserId() {
  return "maidsafe";
}
#  endif

#else
const std::string kVaultName("lifestuff_vault" + kExecutableExtension);

#  ifndef MAIDSAFE_WIN32
inline std::string GetUserId() {
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
