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

#include "maidsafe/common/log.h"
#include "maidsafe/common/return_codes.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "boost/date_time/posix_time/posix_time_duration.hpp"

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

int GetNumRunningProcesses() {
  std::string dummy(detail::kDummyName);
#ifdef MAIDSAFE_WIN32
  std::string command("tasklist /fi \"imagename eq " + dummy +
                      "\" | find /c /v /nh \"~~~\" > process_count.txt");
#else
  std::string command("ps -ef | grep " + dummy + " | wc -l > process_count.txt");
#endif
  system(command.c_str());

  std::string process_string;
  ReadFile(fs::path(".") / "process_count.txt", &process_string);
  process_string = process_string.substr(0, process_string.size() - 1);
  try {
#ifdef MAIDSAFE_WIN32
    // In Windows, adjust for one extra carriage return
    int num_processes(boost::lexical_cast<int>(process_string) - 1);
#else
    // In UNIX, adjust for the two extra commands containing kDUmmyName that we invoked - the
    // overall ps and the piped grep
    int num_processes(boost::lexical_cast<int>(process_string) - 2);
#endif
    return num_processes;
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
    return 0;
  }
}

TEST(InvigilatorTest, BEH_StartStop) {
  // test case for startup (non-existent config file)
  boost::system::error_code error_code;
  {
    if (fs::exists(fs::path(".") / Invigilator::kConfigFileName(), error_code))
      fs::remove(fs::path(".") / Invigilator::kConfigFileName(), error_code);
    ASSERT_FALSE(fs::exists(fs::path(".") / Invigilator::kConfigFileName(), error_code));
    Invigilator invigilator;
    ClientController client_controller;
    int max_seconds = Invigilator::kMaxUpdateInterval().total_seconds();
    EXPECT_FALSE(client_controller.SetUpdateInterval(bptime::seconds(max_seconds + 1)));
    EXPECT_TRUE(client_controller.SetUpdateInterval(bptime::seconds(max_seconds)));
    int min_seconds = Invigilator::kMinUpdateInterval().total_seconds();
    EXPECT_TRUE(client_controller.SetUpdateInterval(bptime::seconds(min_seconds)));
    EXPECT_FALSE(client_controller.SetUpdateInterval(bptime::seconds(min_seconds - 1)));
    Sleep(boost::posix_time::seconds(2));
    EXPECT_TRUE(fs::exists(fs::path(".") / Invigilator::kConfigFileName(), error_code));
    EXPECT_EQ(0, GetNumRunningProcesses());
  }
  std::string config_contents;
  maidsafe::ReadFile(fs::path(".") / Invigilator::kConfigFileName(), &config_contents);
  protobuf::InvigilatorConfig invigilator_config;
  invigilator_config.ParseFromString(config_contents);
  EXPECT_EQ(0, invigilator_config.vault_info_size());

  // test case for existing config file with minimum content (generated in previous test case)
  // One vault is started. This should then be shut down and saved to the config file when the
  // Invigilator is destroyed.
  {
    Invigilator invigilator;
    ClientController client_controller;
    asymm::Keys keys;
    ASSERT_EQ(kSuccess, rsa::GenerateKeyPair(&keys));
    keys.identity = "FirstVault";
    EXPECT_TRUE(client_controller.StartVault(keys, "F"));
    Sleep(boost::posix_time::seconds(1));
    EXPECT_EQ(1, GetNumRunningProcesses());
    Sleep(boost::posix_time::seconds(1));
    EXPECT_TRUE(fs::exists(fs::path(".") / Invigilator::kConfigFileName(), error_code));
  }
  EXPECT_EQ(0, GetNumRunningProcesses());
  config_contents = "";
  maidsafe::ReadFile(fs::path(".") / Invigilator::kConfigFileName(), &config_contents);
  invigilator_config.ParseFromString(config_contents);
  EXPECT_EQ(1, invigilator_config.vault_info_size());

  // test case for existing config file with one vault (generated in previous test case)
  // Two vaults are started - one by config, one by a client. They should then be shut down and
  // both saved to the config file when the Invigilator is destroyed.
  {
    Invigilator invigilator;
    ClientController client_controller;
    asymm::Keys keys;
    ASSERT_EQ(kSuccess, rsa::GenerateKeyPair(&keys));
    keys.identity = "SecondVault";
    EXPECT_TRUE(client_controller.StartVault(keys, "G"));
    Sleep(boost::posix_time::seconds(2));
    EXPECT_EQ(2, GetNumRunningProcesses());
    Sleep(boost::posix_time::seconds(1));
    EXPECT_TRUE(fs::exists(fs::path(".") / Invigilator::kConfigFileName(), error_code));
  }
  EXPECT_EQ(0, GetNumRunningProcesses());
  config_contents = "";
  maidsafe::ReadFile(fs::path(".") / Invigilator::kConfigFileName(), &config_contents);
  invigilator_config.ParseFromString(config_contents);
  EXPECT_EQ(2, invigilator_config.vault_info_size());
}

}  // namespace test

}  // namespace process_management

}  // namespace priv

}  // namespace maidsafe
