/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <boost/program_options.hpp>
#include <boost/process.hpp>
#include <string>
#include <vector>
#include <iostream>
#include <fstream>
#include <iterator>
#include <sys/wait.h>
namespace po = boost::program_options;
namespace bp = ::boost::process;

//bp::child start_child() {
//    std::string exec = "protoc";
//    std::vector<std::string> args;
//    args.push_back("protoc");
//    args.push_back(" --version");
//    bp::context ctx;
//    ctx.stdout_behavior = bp::silence_stream();
//    return bp::launch(exec, args, ctx);
//}

//using namespace std;

//// A helper function to simplify the main part.
//template<class T>
//ostream& operator<<(ostream& os, const vector<T>& v)
//{
//    copy(v.begin(), v.end(), ostream_iterator<T>(os, " "));
//    return os;
//}

int GetOptions(int /*ac*/, char* /*av*/[]) {
  /*try {
    int opt;
    std::string config_file;

    // Declare a group of options that will be
    // allowed only on command line
    po::options_description generic("Generic options");
    generic.add_options()
        ("version,v", "print version string")
        ("help", "produce help message")
        ("config,c", po::value<std::string>(&config_file)->default_value("vault.cfg"),
         "name of a file of a configuration.");

    // Declare a group of options that will be
    // allowed both on command line and in
    // config file
    po::options_description config("Configuration");
    config.add_options()
        ("optimization", po::value<int>(&opt)->default_value(10),
         "optimization level")
        ("include-path,I",
         po::value< std::vector<std::string> >()->composing(),
         "include path")  ;
    // Hidden options, will be allowed both on command line and
    // in config file, but will not be shown to the user.
    po::options_description hidden("Hidden options");
    hidden.add_options()
        ("input-file", po::value< std::vector<std::string> >(), "input file");

    po::options_description cmdline_options;
    cmdline_options.add(generic).add(config).add(hidden);

    po::options_description config_file_options;
    config_file_options.add(config).add(hidden);

    po::options_description visible("Allowed options");
    visible.add(generic).add(config);

    po::positional_options_description p;
    p.add("input-file", -1);

    po::variables_map vm;
    store(po::command_line_parser(ac, av).
          options(cmdline_options).positional(p).run(), vm);
    notify(vm);

    std::ifstream ifs(config_file.c_str());
    if (!ifs) {
      store(parse_config_file(ifs, config_file_options), vm);
      notify(vm);
    }

    if (vm.count("help")) {
      std::cout << visible << "\n";
      return 0;
    }

    if (vm.count("version")) {
      std::cout << "LifeStuff Vault, version 1.0\n";
      return 0;
    }

    if (vm.count("include-path")) {
      std::cout << "Include paths are: "
           << vm["include-path"].as<std::vector<std::string>>() << "\n";
    }

    if (vm.count("input-file")) {
      std::cout << "Input files are: "
           << vm["input-file"].as<std::vector<std::string>> << "\n";
    }

    std::cout << "Using  " << opt << " Gb of disk space for all vaults\n";
  }
  catch(std::exception& e)  {
    std::cout << e.what() << "\n";
    return 1;
  }*/
  return 0;
}

#include <boost/process.hpp>
#include <boost/thread.hpp>
#include <boost/assign/list_of.hpp>
#include <string>
#include <vector>

using namespace boost::process;

int main(int /*ac*/, char* /*av*/[])
{
  /*GetOptions(ac,av);
  std::string exec = find_executable_in_path("TESTcommon");
  std::vector<std::string> args = boost::assign::list_of("TESTcommon")("--gtest_list_tests");
  posix_context ctx;
  ctx.environment = self::get_environment();
  child c = posix_launch(exec, args, ctx);
  posix_status s = c.wait();
  if (s.exited())
    std::cout << s.exit_status() << std::endl;
  if (s.signaled())
    std::cout << s.term_signal() << std::endl;*/
  return 0;
}

