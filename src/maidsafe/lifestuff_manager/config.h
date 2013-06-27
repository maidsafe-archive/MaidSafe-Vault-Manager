/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_CONFIG_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_CONFIG_H_

#include <string>

#include "maidsafe/common/config.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/utils.h"


namespace maidsafe {

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
    // TODO(Team): Distinguish between the supported Linux distros.
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
#ifdef TESTING
const std::string kDownloadManagerSite("dev.goLifestuff.com");
#else
const std::string kDownloadManagerSite("goLifestuff.com");
#endif
const std::string kDownloadManagerProtocol("http");

#ifndef MAIDSAFE_WIN32
inline std::string GetUserId() {
  char user_name[64] = {0};
  int result(getlogin_r(user_name, sizeof(user_name) - 1));
  if (0 != result)
    return "";
  return std::string(user_name);
}
#endif

#ifdef USE_DUMMY_VAULT
const std::string kVaultName("dummy_vault" + kExecutableExtension);
#else
const std::string kVaultName("lifestuff_vault" + kExecutableExtension);
#endif

}  // namespace detail

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_CONFIG_H_
