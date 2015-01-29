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

#include <string>
#include <vector>

#include "boost/filesystem/operations.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/process/execute.hpp"
#include "boost/process/initializers.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/process.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/client_interface.h"

namespace bp = boost::process;
namespace fs = boost::filesystem;

void WaitForStableNetwork() {
  maidsafe::passport::Maid maid{maidsafe::passport::CreateMaidAndSigner().first};
  maidsafe::vault_manager::ClientInterface client_interface{maid};
  client_interface.WaitForStableNetwork().get();
}

void StartNetwork() {
  // Invoke the local_network_controller tool to bring up a local test network.
  fs::path tool_path{maidsafe::process::GetOtherExecutablePath("local_network_controller")};
  if (!fs::exists(tool_path)) {
    LOG(kError) << tool_path << " doesn't exist.  Ensure 'local_network_controller' is built.";
    BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::no_such_element));
  }

  fs::path script_path{maidsafe::ThisExecutableDir() / "network_test_helper.script"};
  if (!fs::exists(script_path)) {
    LOG(kError) << script_path << " doesn't exist.  Ensure 'network_test_helper' is built.";
    BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::no_such_element));
  }

  // We need to improve the scripting to handle optional commands.  In this case, (starting a
  // network), we have an optional command which offers to create or clear the VaultManager root
  // directory.  However, if this folder already exists and is empty, the optional command will not
  // be shown, and the script will fall out of sync.  Until this is handled better, as a workaround
  // we'll create a dummy file in the default root directory so the optional command is always
  // triggered.
  fs::path test_env_root_dir{fs::temp_directory_path() / "MaidSafe_TestNetwork"};
  if (!fs::exists(test_env_root_dir)) {
    if (!fs::create_directories(test_env_root_dir))
      BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::filesystem_io_error));
  } else if (!fs::is_directory(test_env_root_dir)) {
    BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::filesystem_io_error));
  }

  if (fs::is_empty(test_env_root_dir)) {
    if (!fs::create_directory(test_env_root_dir / "script_workaround"))
      BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::filesystem_io_error));
  }

  std::vector<std::string> args{tool_path.string(), script_path.string()};
  bp::execute(bp::initializers::run_exe(tool_path),
              bp::initializers::set_cmd_line(maidsafe::process::ConstructCommandLine(args)),
              bp::initializers::throw_on_error());
}

int main(int argc, char* argv[]) {
  const std::error_code kFailedToConnect{
      maidsafe::make_error_code(maidsafe::VaultManagerErrors::failed_to_connect)};
  const int kUnknownError{
      maidsafe::ErrorToInt(maidsafe::MakeError(maidsafe::CommonErrors::unknown))};
  // See if a local test network is already running.
  try {
    auto unuseds(maidsafe::log::Logging::Instance().Initialise(argc, argv));
    if (unuseds.size() != 1U)  // i.e. if there are any command line args
      BOOST_THROW_EXCEPTION(maidsafe::MakeError(maidsafe::CommonErrors::invalid_parameter));
    WaitForStableNetwork();
    return 0;
  } catch (const maidsafe::maidsafe_error& error) {
    if (error.code() != kFailedToConnect) {
      TLOG(kRed) << boost::diagnostic_information(error) << "\n\n";
      return maidsafe::ErrorToInt(error);
    }
  } catch (const std::exception& e) {
    TLOG(kRed) << e.what() << "\n\n";
    return kUnknownError;
  }

  // There isn't a local test network running, so start one.
  try {
    StartNetwork();
  } catch (const maidsafe::maidsafe_error& error) {
    TLOG(kRed) << boost::diagnostic_information(error) << "\n\n";
    return maidsafe::ErrorToInt(error);
  } catch (const std::exception& e) {
    TLOG(kRed) << e.what() << "\n\n";
    return kUnknownError;
  }

  // Try to connect more than once to the local network's vault_manager, since it won't be#
  // immediately available.
  for (int attempts(0); attempts < 5; ++attempts) {
    try {
      WaitForStableNetwork();
      return 0;
    } catch (const maidsafe::maidsafe_error& error) {
      if (error.code() != kFailedToConnect) {
        TLOG(kRed) << boost::diagnostic_information(error) << "\n\n";
        return maidsafe::ErrorToInt(error);
      }
    }
  }

  return kUnknownError;
}
