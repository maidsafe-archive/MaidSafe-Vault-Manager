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

#include "maidsafe/private/cli.h"

#include <fstream>
#include <iostream>
#include <istream>
#include <ostream>
#include <string>
#include <vector>

#include "boost/program_options.hpp"


namespace maidsafe {

namespace po = boost::program_options;

Cli::Cli(const po::options_description &desc) : desc_(desc), prompt_(">> "), running_(false) {}

void Cli::ReadLine(std::string line)  {
  std::vector<std::string> args;
  line = std::string("--") + line;  // turn first word into an option (long version --)
  // we could check size of first option and also allow short version args as well (-)
  boost::char_separator<char> sep(" ");  // split up command line in a cross platform way
  boost::tokenizer< boost::char_separator<char> > tokens(line, sep);
  for (const auto& t : tokens) {
    args.push_back(t);
  }

  try  {
    po::variables_map vm;
    po::store(po::command_line_parser(args).options(desc_).run(), vm);
    po::notify(vm);
  } catch (po::error  &e) {
    std::cerr << "error: " << e.what() << std::endl;
  }
}

void Cli::Run(std::istream &input_stream) {
  std::string command;
  std::cout << prompt_ << std::flush;
  while (std::getline(input_stream, command, '\n')) {
    ReadLine(command);
    std::cout << prompt_ << std::flush;
  }
}

void Cli::SetPrompt(std::string prompt) {
  prompt_ = prompt;
}

}  // namespace maidsafe
