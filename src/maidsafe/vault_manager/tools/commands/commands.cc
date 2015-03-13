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

#include <algorithm>
#include <iostream>

#include "boost/algorithm/string.hpp"
#include "boost/filesystem/operations.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/vault_manager/tools/local_network_controller.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace tools {

const std::string Command::kPrompt_ = "\n>> ";
const std::string Command::kQuitCommand_ = "q";
const std::string Command::kSeparator_ =
    "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~";

Command::Command(LocalNetworkController* local_network_controller, std::string preamble,
                 std::string instructions, std::string title)
    : local_network_controller_(local_network_controller),
      kPreamble_(std::move(preamble)),
      kInstructions_("\n\n" + kPreamble_ + std::move(instructions)),
      kTitle_(std::move(title)) {
  assert(
      !std::any_of(std::begin(kPreamble_), std::end(kPreamble_), [](char c) { return c == '\n'; }));
}

void Command::PrintTitle() const {
  if (!kTitle_.empty())
    TLOG(kDefaultColour) << "\n\n" << kTitle_ << '\n' << std::string(kTitle_.size(), '=');
}

std::pair<std::string, Command::Source> Command::GetLine() {
  std::pair<std::string, Command::Source> line_and_source;
  while (!local_network_controller_->script_commands.empty() &&
         local_network_controller_->script_commands.front().substr(0, 4) == "### ") {
    local_network_controller_->script_commands.pop_front();
  }
  if (local_network_controller_->script_commands.empty()) {
    line_and_source.second = Source::kStdCin;
    // On Unix, when a child process stops, it causes the eof bit to get set in std::cin.
    const int kMaxClearAttempts{1000};
    int clear_attempts{0};
    while (!std::getline(std::cin, line_and_source.first) && clear_attempts < kMaxClearAttempts) {
      if (std::cin.eof()) {
        std::cin.clear();
        ++clear_attempts;
      } else {
        TLOG(kRed) << "Error reading from std::cin.\n";
        BOOST_THROW_EXCEPTION(MakeError(CommonErrors::unknown));
      }
    }
  } else {
    line_and_source.first = local_network_controller_->script_commands.front();
    local_network_controller_->script_commands.pop_front();
    line_and_source.second = Source::kScript;
    TLOG(kDefaultColour) << line_and_source.first << '\n';
  }
  CheckForExitCommand(line_and_source.first);
  local_network_controller_->entered_commands.push_back("### " + kPreamble_ + '\n' +
                                                        line_and_source.first);
  return line_and_source;
}

template <>
bool Command::ConvertAndValidateChoice<int, int, int>(const std::string& choice_as_string,
                                                      int& choice, const int* const default_choice,
                                                      int min, int max) {
  if (choice_as_string.empty() && default_choice)
    choice = *default_choice;
  else
    choice = std::stoi(choice_as_string);

  if (choice < min || choice > max)
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_argument));

  return true;
}

template <>
bool Command::ConvertAndValidateChoice<boost::filesystem::path, bool>(
    const std::string& choice_as_string, boost::filesystem::path& choice,
    const boost::filesystem::path* const default_choice, bool must_exist) {
  on_scope_exit clear_path{[&choice] { choice.clear(); }};
  if (choice_as_string.empty() && default_choice)
    choice = *default_choice;
  else
    choice = fs::path{choice_as_string};

  if (must_exist && !fs::exists(choice)) {
    TLOG(kRed) << "\n" << choice_as_string << " doesn't exist.\n";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_argument));
  }

  clear_path.Release();
  return true;
}

template <>
bool Command::ConvertAndValidateChoice<bool>(const std::string& choice_as_string, bool& choice,
                                             const bool* const default_choice) {
  if (choice_as_string.empty() && default_choice) {
    choice = *default_choice;
    return true;
  } else if (choice_as_string == "y" || choice_as_string == "Y") {
    choice = true;
    return true;
  } else if (choice_as_string == "n" || choice_as_string == "N") {
    choice = false;
    return true;
  }
  BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_argument));
}

template <>
bool Command::ConvertAndValidateChoice<std::string>(const std::string& choice_as_string,
                                                    std::string& choice,
                                                    const std::string* const default_choice) {
  choice = (choice_as_string.empty() && default_choice) ? *default_choice : choice_as_string;
  return true;
}

void Command::CheckForExitCommand(const std::string& input_command) const {
  if (boost::to_lower_copy(input_command) == kQuitCommand_)
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::success));
}

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe
