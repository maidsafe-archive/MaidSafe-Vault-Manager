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

#ifndef MAIDSAFE_VAULT_MANAGER_TOOLS_COMMANDS_COMMANDS_H_
#define MAIDSAFE_VAULT_MANAGER_TOOLS_COMMANDS_COMMANDS_H_

#include <string>
#include <utility>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/log.h"

namespace maidsafe {

namespace vault_manager {

namespace tools {

struct LocalNetworkController;

class Command {
 public:
  Command(LocalNetworkController* local_network_controller, std::string preamble,
          std::string instructions, std::string title = "");
  virtual ~Command() {}
  void PrintTitle() const;
  virtual void GetChoice() = 0;
  virtual void HandleChoice() = 0;

 protected:
  template <typename Choice, typename... Args>
  bool DoGetChoice(Choice& choice, const Choice* const default_choice, Args... args);

  template <typename Choice, typename... Args>
  bool ConvertAndValidateChoice(const std::string& choice_as_string, Choice& choice,
                                const Choice* const default_choice, Args... args);

  LocalNetworkController* local_network_controller_;
  const std::string kPreamble_, kInstructions_, kTitle_;
  static const std::string kPrompt_, kQuitCommand_, kSeparator_;

 private:
  enum class Source { kScript, kStdCin };
  std::pair<std::string, Source> GetLine();
  void CheckForExitCommand(const std::string& input_command) const;
};



template <typename Choice, typename... Args>
bool Command::DoGetChoice(Choice& choice, const Choice* const default_choice, Args... args) {
  std::pair<std::string, Source> line_and_source{GetLine()};
  try {
    return ConvertAndValidateChoice(line_and_source.first, choice, default_choice, args...);
  } catch (const std::exception&) {
    TLOG(kRed) << "\n" << line_and_source.first << " is not a valid choice.\n";
    if (line_and_source.second == Source::kScript)
      throw;
    return false;
  }
}

template <>
bool Command::ConvertAndValidateChoice<int, int, int>(const std::string& choice_as_string,
                                                      int& choice, const int* const default_choice,
                                                      int min, int max);

template <>
bool Command::ConvertAndValidateChoice<boost::filesystem::path, bool>(
    const std::string& choice_as_string, boost::filesystem::path& chosen_path,
    const boost::filesystem::path* const default_choice, bool must_exist);

template <>
bool Command::ConvertAndValidateChoice<bool>(const std::string& choice_as_string, bool& choice,
                                             const bool* const default_choice);

template <>
bool Command::ConvertAndValidateChoice<std::string>(const std::string& choice_as_string,
                                                    std::string& choice,
                                                    const std::string* const default_choice);

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_TOOLS_COMMANDS_COMMANDS_H_
