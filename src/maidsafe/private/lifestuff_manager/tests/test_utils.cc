/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "maidsafe/private/lifestuff_manager/tests/test_utils.h"

#include <cstdlib>

#include "boost/algorithm/string/find_iterator.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/lifestuff_manager/config.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

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
    int num_processes(boost::lexical_cast<int>(process_string));
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

}  //  namespace priv

}  //  namespace maidsafe
