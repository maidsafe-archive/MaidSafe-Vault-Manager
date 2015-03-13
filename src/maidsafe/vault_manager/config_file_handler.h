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

#ifndef MAIDSAFE_VAULT_MANAGER_CONFIG_FILE_HANDLER_H_
#define MAIDSAFE_VAULT_MANAGER_CONFIG_FILE_HANDLER_H_

#include <mutex>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/passport/types.h"

namespace maidsafe {

namespace vault_manager {

struct VaultInfo;

class ConfigFileHandler {
 public:
  explicit ConfigFileHandler(boost::filesystem::path config_file_path);
  std::vector<VaultInfo> ReadConfigFile() const;
  void WriteConfigFile(std::vector<VaultInfo> vaults) const;
  const crypto::AES256KeyAndIV& SymmKeyAndIV() const { return kSymmKeyAndIV_; }

 private:
  ConfigFileHandler(const ConfigFileHandler&) = delete;
  ConfigFileHandler(ConfigFileHandler&&) = delete;
  ConfigFileHandler operator=(ConfigFileHandler) = delete;

  void CreateConfigFile();

  boost::filesystem::path config_file_path_;
  mutable std::mutex mutex_;
  const crypto::AES256KeyAndIV kSymmKeyAndIV_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_CONFIG_FILE_HANDLER_H_
