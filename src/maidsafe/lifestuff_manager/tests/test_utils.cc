/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#include "maidsafe/lifestuff_manager/tests/test_utils.h"

#include <cstdlib>

#include "boost/algorithm/string/find_iterator.hpp"
#include "boost/algorithm/string/trim.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff_manager/config.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace lifestuff_manager {

namespace test {

int GetNumRunningProcesses(const std::string& process_name) {
#ifdef MAIDSAFE_WIN32
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
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return -1;
  }
}

}  // namespace test

}  //  namespace lifestuff_manager

}  //  namespace maidsafe
