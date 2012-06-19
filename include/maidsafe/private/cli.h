/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_PRIVATE_SIGNING_TOOL_H_
#define MAIDSAFE_PRIVATE_SIGNING_TOOL_H_

#include <vector>
#include <string>
#include <iostream>
#include <iterator>
#include <boost/bind.hpp>
#include <boost/program_options.hpp>
#include<boost/tokenizer.hpp>


namespace maidsafe {

namespace po = boost::program_options;

class Cli {
 public:
  Cli(const po::options_description &desc);
  void ReadLine(std::string line);
  void Run(std::istream &input_stream);
  void SetPrompt(std::string prompt);
  void PrintHelp();
private:
  const po::options_description &desc_;
  std::string  prompt_;
  bool running_;
};

} // namespace maidsafe


#endif  // MAIDSAFE_PRIVATE_SIGNING_TOOL_H_
