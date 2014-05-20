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

#include "maidsafe/vault_manager/tools/local_network_controller.h"

#include <fstream>

#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"

#include "maidsafe/vault_manager/tools/commands/commands.h"
#include "maidsafe/vault_manager/tools/commands/begin.h"

namespace maidsafe {

namespace vault_manager {

namespace tools {

LocalNetworkController::LocalNetworkController(const boost::filesystem::path& script_path)
    : script_commands(),
      entered_commands(),
      current_command(),
      client_interface(),
      vault_manager() {
  if (!script_path.empty()) {
    if (!boost::filesystem::exists(script_path) ||
        !boost::filesystem::is_regular_file(script_path)) {
      TLOG(kRed) << script_path << " doesn't exist or is not a regular file.\n";
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
    }

    std::ifstream script(script_path.string());
    std::string line;
    while (std::getline(script, line))
      script_commands.emplace_back(std::move(line));
  }
  current_command = maidsafe::make_unique<Begin>(this);
}

LocalNetworkController::~LocalNetworkController() {
  current_command.reset();
  if (entered_commands.empty())
    return;
  TLOG(kDefaultColour) << "\n\nSequence of entered commands:\n\n";
  for (const auto& command : entered_commands)
    TLOG(kDefaultColour) << command << '\n';
  TLOG(kDefaultColour) << "\n\n";
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
