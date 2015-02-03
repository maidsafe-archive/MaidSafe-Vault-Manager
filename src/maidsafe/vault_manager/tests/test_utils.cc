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

#include "maidsafe/vault_manager/tests/test_utils.h"

#include <cstdlib>

#include "boost/algorithm/string/find_iterator.hpp"
#include "boost/algorithm/string/trim.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/config.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/vault_manager/config.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace test {

int GetNumRunningProcesses(std::string process_name) {
#ifdef MAIDSAFE_WIN32
  process_name += ThisExecutablePath().extension().string();
  std::string command("tasklist /fi \"imagename eq " + process_name + "\" /nh > process_count.txt");
#else
  std::string command("ps -ef | grep " + process_name +
                      " | grep -v grep | wc -l > process_count.txt");
#endif
  int result(system(command.c_str()));
  if (result != 0) {
    LOG(kError) << "Failed to execute command that checks processes: " << command;
    return -1;
  }

  try {
    std::string contents(ReadFile(fs::path(".") / "process_count.txt").string());
#ifdef MAIDSAFE_WIN32
    typedef boost::find_iterator<std::string::iterator> StringFindIterator;
    StringFindIterator itr =
        boost::make_find_iterator(contents, boost::first_finder(process_name, boost::is_equal()));
    int num_processes(static_cast<int>(std::distance(itr, StringFindIterator())));
#else
    boost::trim(contents);
    // In UNIX, adjust for the two extra commands containing kDUmmyName that we invoked - the
    // overall ps and the piped grep
    int num_processes(std::stoi(contents));
#endif
    return num_processes;
  } catch (const std::exception& e) {
    LOG(kError) << e.what();
    return -1;
  }
}

}  // namespace test

}  //  namespace vault_manager

}  //  namespace maidsafe
