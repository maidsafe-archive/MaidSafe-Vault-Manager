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

#include "maidsafe/vault_manager/config_file_handler.h"

#include <string>

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/serialisation/serialisation.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/config_file.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace {

ConfigFile ParseConfigFile(const fs::path& config_file_path, std::mutex& mutex) {
  std::string content;
  {
    std::lock_guard<std::mutex> lock{mutex};
    content = ReadFile(config_file_path).string();
  }
  return ConvertFromString<ConfigFile>(content);
}

crypto::AES256Key InitialiseKey(const fs::path& config_file_path, std::mutex& mutex) {
  boost::system::error_code error_code;
  if (!fs::exists(config_file_path, error_code) ||
      error_code.value() == boost::system::errc::no_such_file_or_directory) {
    return crypto::AES256Key{RandomString(crypto::AES256_KeySize)};
  }
  ConfigFile config{ParseConfigFile(config_file_path, mutex)};
  return config.symm_key;
}

crypto::AES256InitialisationVector InitialiseIv(const fs::path& config_file_path,
                                                std::mutex& mutex) {
  boost::system::error_code error_code;
  if (!fs::exists(config_file_path, error_code) ||
      error_code.value() == boost::system::errc::no_such_file_or_directory) {
    return crypto::AES256InitialisationVector{RandomString(crypto::AES256_IVSize)};
  }
  ConfigFile config{ParseConfigFile(config_file_path, mutex)};
  return config.symm_iv;
}

}  // unnamed namespace

ConfigFileHandler::ConfigFileHandler(fs::path config_file_path)
    : config_file_path_(std::move(config_file_path)),
      mutex_(),
      kSymmKey_(InitialiseKey(config_file_path_, mutex_)),
      kSymmIv_(InitialiseIv(config_file_path_, mutex_)) {
  boost::system::error_code error_code;
  if (!fs::exists(config_file_path_, error_code) ||
      error_code.value() == boost::system::errc::no_such_file_or_directory) {
    CreateConfigFile();
  }
}

void ConfigFileHandler::CreateConfigFile() {
  ConfigFile config(kSymmKey_, kSymmIv_, std::vector<VaultInfo>{});

  boost::system::error_code error_code;
  if (!fs::exists(config_file_path_.parent_path(), error_code)) {
    if (!fs::create_directories(config_file_path_.parent_path(), error_code) || error_code) {
      LOG(kError) << "Failed to create directories for config file " << config_file_path_ << ": "
                  << error_code.message();
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::filesystem_io_error));
    }
  }

  std::lock_guard<std::mutex> lock{mutex_};
  if (!WriteFile(config_file_path_, ConvertToString(config))) {
    LOG(kError) << "Failed to create config file " << config_file_path_;
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::filesystem_io_error));
  }
  LOG(kInfo) << "Created config file " << config_file_path_;
}

std::vector<VaultInfo> ConfigFileHandler::ReadConfigFile() const {
  ConfigFile config{ParseConfigFile(config_file_path_, mutex_)};
  assert(config.symm_key == kSymmKey_ && config.symm_iv == kSymmIv_);
  return config.vaults;
}

void ConfigFileHandler::WriteConfigFile(std::vector<VaultInfo> vaults) const {
  ConfigFile config(kSymmKey_, kSymmIv_, std::move(vaults));
  std::lock_guard<std::mutex> lock{mutex_};
  if (!WriteFile(config_file_path_, ConvertToString(config))) {
    LOG(kError) << "Failed to write config file " << config_file_path_;
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::filesystem_io_error));
  }
}

}  // namespace vault_manager

}  // namespace maidsafe
