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
      script_command_(),
      kDefaultOutput_(">> "),
      kTitle_(std::move(title)),
      exit_(false) {
  assert(!kTitle_.empty());
}

Command::~Command() {
  TLOG(kDefaultColour) << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n\n";
}

bool Command::PopScriptCommand() {
  if (local_network_controller_->script_commands.empty()) {
    script_command_.clear();
    return false;
  } else {
    script_command_ = local_network_controller_->script_commands.front();
    local_network_controller_->script_commands.pop_front();
    return true;
  }
}

void Command::PrintTitle() const {
  TLOG(kDefaultColour) << kTitle_ << '\n' << std::string(kTitle_.size(), '=') << '\n';
}

bool Command::GetIntChoice(int& choice, const int* const default_choice, int min, int max) {
  bool got_from_script{ PopScriptCommand() };
  std::string chosen_int_as_string{ script_command_ };
  try {
    if (got_from_script)
      TLOG(kDefaultColour) << chosen_int_as_string << '\n';
    else
      std::getline(std::cin, chosen_int_as_string);

    if (chosen_int_as_string == "exit") {
      exit_ = true;
      return true;
    }

    if (chosen_int_as_string.empty() && default_choice)
      choice = *default_choice;
    else
      choice = std::stoi(chosen_int_as_string);

    if (choice < min || choice > max)
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));

    return true;
  }
  catch (const std::exception&) {
    TLOG(kRed) << chosen_int_as_string << " is not a valid choice.\n";
    if (got_from_script)
      throw;
    return false;
  }
}

bool Command::GetPathChoice(fs::path& chosen_path, const fs::path* const default_choice,
                            bool must_exist) {
  bool got_from_script{ PopScriptCommand() };
  std::string chosen_path_as_string{ script_command_ };
  try {
    if (got_from_script)
      TLOG(kDefaultColour) << chosen_path_as_string << '\n';
    else
      std::getline(std::cin, chosen_path_as_string);

    if (chosen_path_as_string == "exit") {
      exit_ = true;
      return true;
    }

    if (chosen_path_as_string.empty() && default_choice)
      chosen_path = *default_choice;
    else
      chosen_path = fs::path{ chosen_path_as_string };

    if (must_exist && !fs::exists(chosen_path)) {
      TLOG(kRed) << chosen_path_as_string << " doesn't exist.\n";
      BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
    }

    return true;
  }
  catch (const std::exception&) {
    chosen_path.clear();
    TLOG(kRed) << chosen_path_as_string << " is not a valid choice.\n";
    if (got_from_script)
      throw;
    return false;
  }
}

bool Command::GetBoolChoice(bool& choice, const bool* const default_choice) {
  bool got_from_script{ PopScriptCommand() };
  std::string choice_as_string{ script_command_ };
  try {
    if (got_from_script)
      TLOG(kDefaultColour) << choice_as_string << '\n';
    else
      std::getline(std::cin, choice_as_string);

    if (choice_as_string == "exit") {
      exit_ = true;
      return true;
    }

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
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  catch (const std::exception&) {
    TLOG(kRed) << choice_as_string << " is not a valid choice.\n";
    if (got_from_script)
      throw;
    return false;
  }
}

}  // namepsace tools

}  // namespace vault_manager

}  // namespace maidsafe
