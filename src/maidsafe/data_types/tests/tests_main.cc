/*  Copyright 2009 MaidSafe.net limited

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

#include "boost/program_options.hpp"

#include "maidsafe/common/test.h"

int main(int argc, char** argv) {
  auto unused_options(maidsafe::log::Logging::Instance().Initialise(argc, argv));
  boost::program_options::options_description no_option("");
  boost::program_options::parsed_options parsed(
    boost::program_options::command_line_parser(unused_options).options(no_option).
      allow_unregistered().run());
  boost::program_options::variables_map variables_map;
  boost::program_options::store(parsed, variables_map);
  boost::program_options::notify(variables_map);
  unused_options = boost::program_options::collect_unrecognized(
      parsed.options, boost::program_options::include_positional);
  argc = static_cast<int>(unused_options.size() + 1);
  int position(0);
  for (const auto& unused_option : unused_options)
    std::strcpy(argv[++position], unused_option.c_str());  // NOLINT
  return maidsafe::test::ExecuteMain(argc, argv);
}
