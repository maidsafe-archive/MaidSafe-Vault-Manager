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

#include <limits>
#include <string>

#include "boost/filesystem/path.hpp"

namespace maidsafe {

namespace vault_manager {

namespace tools {

struct LocalNetworkController;

class Command {
 public:
  Command(LocalNetworkController* local_network_controller, std::string title);
  virtual ~Command();
  void PrintTitle() const;
  virtual void PrintOptions() const = 0;
  virtual void GetChoice() = 0;
  virtual void HandleChoice() = 0;

 protected:
  bool PopScriptCommand();
  bool GetIntChoice(int& choice, const int* const default_choice = nullptr, int min = 1,
                    int max = std::numeric_limits<int>::max());
  bool GetPathChoice(boost::filesystem::path& chosen_path,
                     const boost::filesystem::path* const default_choice,
                     bool must_exist);
  bool GetBoolChoice(bool& choice, const bool* const default_choice);

  LocalNetworkController* local_network_controller_;
  std::string script_command_;
  const std::string kDefaultOutput_;
  const std::string kTitle_;
  bool exit_;
};

}  // namespace tools

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_TOOLS_COMMANDS_COMMANDS_H_
