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

#include "boost/date_time/posix_time/posix_time_duration.hpp"
#include "boost/algorithm/string.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/return_codes.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/process_management/client_controller.h"
#include "maidsafe/private/process_management/vault_controller.h"
#include "maidsafe/private/process_management/invigilator.h"
#include "maidsafe/private/process_management/vault_info_pb.h"
#include "maidsafe/private/process_management/utils.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace priv {

namespace process_management {

namespace test {

namespace {

int GetNumRunningProcesses() {
  std::string dummy(detail::kDummyName);
#ifdef MAIDSAFE_WIN32
  std::string command("tasklist /fi \"imagename eq " + dummy + ".exe\" /nh > process_count.txt");
#else
  std::string command("ps -ef | grep " + dummy + " | wc -l > process_count.txt");
#endif
  int result(system(command.c_str()));
  if (result != 0) {
    LOG(kError) << "Failed to execute command that checks processes: " << command;
    return -1;
  }

  try {
#ifdef MAIDSAFE_WIN32
    int num_processes(0);
    char process_info[256];
    std::streamsize number_of_characters(256);
    fs::path file_path(fs::path(".") / "process_count.txt");
    std::ifstream file(file_path.string().c_str(), std::ios_base::binary);
    if (!file.good())
      return num_processes;
    while (file.getline(process_info, number_of_characters))
      ++num_processes;
    num_processes -= 1;
#else
    std::string process_string;
    ReadFile(fs::path(".") / "process_count.txt", &process_string);
    boost::trim(process_string);
    // In UNIX, adjust for the two extra commands containing kDUmmyName that we invoked - the
    // overall ps and the piped grep
    int num_processes(boost::lexical_cast<int>(process_string) - 2);
#endif
    return num_processes;
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return -1;
  }
}

}  // namespace

TEST(InvigilatorTest, FUNC_StartStop) {
  maidsafe::log::Logging::instance().AddFilter("private", maidsafe::log::kVerbose);

  // test case for startup (non-existent config file)
  boost::system::error_code error_code;
  {
    if (fs::exists(fs::path(".") / detail::kGlobalConfigFilename, error_code))
      fs::remove(fs::path(".") / detail::kGlobalConfigFilename, error_code);
    ASSERT_FALSE(fs::exists(fs::path(".") / detail::kGlobalConfigFilename, error_code));
    Invigilator invigilator;
    ClientController client_controller;
    int max_seconds = Invigilator::kMaxUpdateInterval().total_seconds();
    EXPECT_FALSE(client_controller.SetUpdateInterval(bptime::seconds(max_seconds + 1)));
    EXPECT_TRUE(client_controller.SetUpdateInterval(bptime::seconds(max_seconds)));
    int min_seconds = Invigilator::kMinUpdateInterval().total_seconds();
    EXPECT_TRUE(client_controller.SetUpdateInterval(bptime::seconds(min_seconds)));
    EXPECT_FALSE(client_controller.SetUpdateInterval(bptime::seconds(min_seconds - 1)));
    Sleep(boost::posix_time::seconds(2));
    EXPECT_TRUE(fs::exists(fs::path(".") / detail::kGlobalConfigFilename, error_code));
    EXPECT_EQ(0, GetNumRunningProcesses());
  }
  std::string config_contents;
  maidsafe::ReadFile(fs::path(".") / detail::kGlobalConfigFilename, &config_contents);
  protobuf::InvigilatorConfig invigilator_config;
  invigilator_config.ParseFromString(config_contents);
  EXPECT_EQ(0, invigilator_config.vault_info_size());

  // test case for existing config file with minimum content (generated in previous test case)
  // One vault is started. This should then be shut down and saved to the config file when the
  // Invigilator is destroyed.
  asymm::Keys first_keys;
  {
    Invigilator invigilator;
    ClientController client_controller;
    ASSERT_EQ(kSuccess, asymm::GenerateKeyPair(&first_keys));
    first_keys.identity = "FirstVault";
    EXPECT_TRUE(client_controller.StartVault(first_keys, "F"));
    Sleep(boost::posix_time::seconds(1));
    EXPECT_EQ(1, GetNumRunningProcesses());
    Sleep(boost::posix_time::seconds(1));
    EXPECT_TRUE(fs::exists(fs::path(".") / detail::kGlobalConfigFilename, error_code));
  }
  EXPECT_EQ(0, GetNumRunningProcesses());
  config_contents = "";
  maidsafe::ReadFile(fs::path(".") / detail::kGlobalConfigFilename, &config_contents);
  invigilator_config.ParseFromString(config_contents);
  EXPECT_EQ(1, invigilator_config.vault_info_size());

  protobuf::BootstrapEndpoints end_points(invigilator_config.bootstrap_endpoints());
  int max_index(end_points.bootstrap_endpoint_ip_size() >
                end_points.bootstrap_endpoint_port_size() ?
                    end_points.bootstrap_endpoint_port_size() :
                    end_points.bootstrap_endpoint_ip_size());
  int endpoint_matches(0);
  for (int n(0); n < max_index; ++n) {
      if (end_points.bootstrap_endpoint_ip(n).compare("127.0.0.46") &&
          (end_points.bootstrap_endpoint_port(n) == 3658)) {
        ++endpoint_matches;
      }
  }
  EXPECT_GE(1, endpoint_matches);

  // test case for existing config file with one vault (generated in previous test case)
  // Two vaults are started - one by config, one by a client. They should then be shut down and
  // both saved to the config file when the Invigilator is destroyed.
  asymm::Keys second_keys;
  {
    Invigilator invigilator;
    ClientController client_controller;
    ASSERT_EQ(kSuccess, asymm::GenerateKeyPair(&second_keys));
    second_keys.identity = "SecondVault";
    EXPECT_TRUE(client_controller.StartVault(second_keys, "G"));
    Sleep(boost::posix_time::seconds(2));
    EXPECT_EQ(2, GetNumRunningProcesses());
    Sleep(boost::posix_time::seconds(1));
    EXPECT_TRUE(fs::exists(fs::path(".") / detail::kGlobalConfigFilename, error_code));
  }
  EXPECT_EQ(0, GetNumRunningProcesses());
  config_contents = "";
  maidsafe::ReadFile(fs::path(".") / detail::kGlobalConfigFilename, &config_contents);
  invigilator_config.ParseFromString(config_contents);
  EXPECT_EQ(2, invigilator_config.vault_info_size());

  // test case for existing config file with two vaults (generated in previous test case)
  // Two vaults are started - both by config. One is then shut down by the client and one is shut
  // down when the Invigilator is destroyed. both should saved to the config file.
  {
    Invigilator invigilator;
    ClientController client_controller;
    EXPECT_EQ(2, GetNumRunningProcesses());
    asymm::PlainText data(RandomString(64));
    asymm::Signature signature1, signature2;
    asymm::Sign(data, first_keys.private_key, &signature1);
    asymm::Sign(data, second_keys.private_key, &signature2);
    EXPECT_TRUE(client_controller.StopVault(data, signature1, "FirstVault"));
    EXPECT_EQ(1, GetNumRunningProcesses());
  }
  EXPECT_EQ(0, GetNumRunningProcesses());
  config_contents = "";
  maidsafe::ReadFile(fs::path(".") / detail::kGlobalConfigFilename, &config_contents);
  invigilator_config.ParseFromString(config_contents);
  ASSERT_EQ(2, invigilator_config.vault_info_size());
  int run_count(0);
  if (invigilator_config.vault_info(0).requested_to_run())
    ++run_count;
  if (invigilator_config.vault_info(1).requested_to_run())
    ++run_count;
  EXPECT_EQ(1, run_count);

  // test case for existing config file with two vaults (generated in previous test case, one
  // deactivated). One vault is started by config. Two clients are then used to start 30 new vaults.
  LOG(kError) << "START TEST 4";
  {
    EXPECT_EQ(0, GetNumRunningProcesses());
    config_contents = "";
    maidsafe::ReadFile(fs::path(".") / detail::kGlobalConfigFilename, &config_contents);
    invigilator_config.ParseFromString(config_contents);
    EXPECT_EQ(2, invigilator_config.vault_info_size());
    Invigilator invigilator;
    EXPECT_EQ(1, GetNumRunningProcesses());
    ClientController client_controller1, client_controller2;
    asymm::Keys keys;
    for (int i(0); i < 50; ++i) {
      ASSERT_EQ(kSuccess, asymm::GenerateKeyPair(&keys));
      keys.identity = RandomAlphaNumericString(64);
      if (i % 2 == 0)
        EXPECT_TRUE(client_controller1.StartVault(keys, RandomAlphaNumericString(16)));
      else
        EXPECT_TRUE(client_controller2.StartVault(keys, RandomAlphaNumericString(16)));
    }
    EXPECT_EQ(51, GetNumRunningProcesses());
  }
  EXPECT_EQ(0, GetNumRunningProcesses());
  config_contents = "";
  maidsafe::ReadFile(fs::path(".") / detail::kGlobalConfigFilename, &config_contents);
  invigilator_config.ParseFromString(config_contents);
  EXPECT_EQ(52, invigilator_config.vault_info_size());
  /*run_count = 0;
  if (invigilator_config.vault_info(0).requested_to_run())
    ++run_count;
  if (invigilator_config.vault_info(1).requested_to_run())
    ++run_count;
  EXPECT_EQ(1, run_count);*/
  boost::system::error_code error;
  fs::remove(fs::path(".") / detail::kGlobalConfigFilename, error);
}

}  // namespace test

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
