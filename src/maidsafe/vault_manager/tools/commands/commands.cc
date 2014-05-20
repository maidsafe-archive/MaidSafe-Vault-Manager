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

#include "maidsafe/vault_manager/tools/commands/commands.h"

#include <iostream>

#include "boost/algorithm/string.hpp"
#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/vault_manager/tools/local_network_controller.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

Command::Command(LocalNetworkController* local_network_controller, std::string title)
    : local_network_controller_(local_network_controller),
      kDefaultOutput_("\n>> "),
      kTitle_(std::move(title)),
      kQuitCommand_("q") {
  assert(!kTitle_.empty());
}

Command::~Command() {
  TLOG(kDefaultColour) << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n";
}

void Command::PrintTitle() const {
  TLOG(kDefaultColour) << kTitle_ << '\n' << std::string(kTitle_.size(), '=') << '\n';
}

std::pair<std::string, Command::Source> Command::GetLine() {
  std::pair<std::string, Command::Source> line_and_source;
  if (local_network_controller_->script_commands.empty()) {
    line_and_source.second = Source::kStdCin;
    std::getline(std::cin, line_and_source.first);
  } else {
    line_and_source.first = local_network_controller_->script_commands.front();
    local_network_controller_->script_commands.pop_front();
    line_and_source.second = Source::kScript;
    TLOG(kDefaultColour) << line_and_source.first << '\n';
  }
  CheckForExitCommand(line_and_source.first);
  return line_and_source;
}

bool Command::GetIntChoice(int& choice, const int* const default_choice, int min, int max) {
  std::pair<std::string, Command::Source> line_and_source{ GetLine() };
  try {
    if (line_and_source.first.empty() && default_choice)
      choice = *default_choice;
    else
      choice = std::stoi(line_and_source.first);

    if (choice < min || choice > max)
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));

    return true;
  }
  catch (const std::exception&) {
    TLOG(kRed) << "\n" << line_and_source.first << " is not a valid choice.\n";
    if (line_and_source.second == Source::kScript)
      throw;
    return false;
  }
}

bool Command::GetPathChoice(fs::path& chosen_path, const fs::path* const default_choice,
                            bool must_exist) {
  std::pair<std::string, Command::Source> line_and_source{ GetLine() };
  try {
    if (line_and_source.first.empty() && default_choice)
      chosen_path = *default_choice;
    else
      chosen_path = fs::path{ line_and_source.first };

    if (must_exist && !fs::exists(chosen_path)) {
      TLOG(kRed) << "\n" << line_and_source.first << " doesn't exist.\n";
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
    }

    return true;
  }
  catch (const std::exception&) {
    chosen_path.clear();
    TLOG(kRed) << "\n" << line_and_source.first << " is not a valid choice.\n";
    if (line_and_source.second == Source::kScript)
      throw;
    return false;
  }
}

bool Command::GetBoolChoice(bool& choice, const bool* const default_choice) {
  std::pair<std::string, Command::Source> line_and_source{ GetLine() };
  try {
    if (line_and_source.first.empty() && default_choice) {
      choice = *default_choice;
      return true;
    } else if (line_and_source.first == "y" || line_and_source.first == "Y") {
      choice = true;
      return true;
    } else if (line_and_source.first == "n" || line_and_source.first == "N") {
      choice = false;
      return true;
    }
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  catch (const std::exception&) {
    TLOG(kRed) << "\n" << line_and_source.first << " is not a valid choice.\n";
    if (line_and_source.second == Source::kScript)
      throw;
    return false;
  }
}

void Command::CheckForExitCommand(const std::string& input_command) const {
  if (boost::to_lower_copy(input_command) == kQuitCommand_)
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::success));
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
