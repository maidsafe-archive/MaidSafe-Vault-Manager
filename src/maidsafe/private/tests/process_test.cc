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

#include <thread>
#include <string>
#include <vector>

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/process_manager.h"

namespace {
  std::string parent_path_;
}

namespace maidsafe {

namespace test {

// TEST(ProcessManagerTest, BEH_StartSingleProcess) {
//   maidsafe::ProcessManager manager;
//   maidsafe::Process test;
//   ASSERT_TRUE(test.SetProcessName("DUMMYprocess"));
//   test.AddArgument("DUMMYprocess");
//   test.AddArgument("--runtime");
//   test.AddArgument("2");
//   test.AddArgument("--nocrash");
//
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   uint32_t num = manager.AddProcess(test);
//   auto start(boost::posix_time::microsec_clock::universal_time());
//   manager.StartProcess(num);
//   EXPECT_GT(num, 0);
//   manager.LetProcessDie(num);
//   manager.WaitForProcesses();
//   auto end(boost::posix_time::microsec_clock::universal_time());
//   boost::posix_time::time_duration elapsed(end - start);
//   int64_t seconds(elapsed.seconds());
//   EXPECT_GE(seconds, 2);
//   EXPECT_LE(seconds, 3);
//   EXPECT_EQ(1, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
// }
//
// TEST(ProcessManagerTest, BEH_KillProcess) {
//   maidsafe::ProcessManager manager;
//   maidsafe::Process test;
//   ASSERT_TRUE(test.SetProcessName("DUMMYprocess"));
//   test.AddArgument("DUMMYprocess");
//   test.AddArgument("--runtime");
//   test.AddArgument("5");
//   test.AddArgument("--nocrash");
//
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   uint32_t num = manager.AddProcess(test);
//   auto start(boost::posix_time::microsec_clock::universal_time());
//   manager.StartProcess(num);
//   EXPECT_GT(num, 0);
//   manager.KillProcess(num);
//   manager.WaitForProcesses();
//   auto end(boost::posix_time::microsec_clock::universal_time());
//   boost::posix_time::time_duration elapsed(end - start);
//   int64_t seconds(elapsed.seconds());
//   EXPECT_LE(seconds, 1);
//   EXPECT_EQ(1, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
// }
//
// TEST(ProcessManagerTest, BEH_RestartProcess) {
//   maidsafe::ProcessManager manager;
//   maidsafe::Process test;
//   ASSERT_TRUE(test.SetProcessName("DUMMYprocess"));
//   test.AddArgument("DUMMYprocess");
//   test.AddArgument("--runtime");
//   test.AddArgument("2");
//   test.AddArgument("--nocrash");
//
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   uint32_t num = manager.AddProcess(test);
//   auto start(boost::posix_time::microsec_clock::universal_time());
//   manager.StartProcess(num);
//   EXPECT_GT(num, 0);
//   manager.RestartProcess(num);
//   Sleep(boost::posix_time::millisec(2000));
//   manager.LetProcessDie(num);
//   manager.WaitForProcesses();
//   auto end(boost::posix_time::microsec_clock::universal_time());
//   boost::posix_time::time_duration elapsed(end - start);
//   int64_t seconds(elapsed.seconds());
//   EXPECT_GE(seconds, 2);
//   EXPECT_LE(seconds, 3);
//   EXPECT_EQ(1, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
// }
//
//
//
// TEST(ProcessManagerTest, BEH_StartThreeProcesses) {
//   maidsafe::ProcessManager manager;
//   maidsafe::Process test;
//   ASSERT_TRUE(test.SetProcessName("DUMMYprocess"));
//   test.AddArgument("DUMMYprocess");
//   test.AddArgument("--runtime");
//   test.AddArgument("2");
//   test.AddArgument("--nocrash");
//
//   maidsafe::Process test1;
//   ASSERT_TRUE(test1.SetProcessName("DUMMYprocess"));
//   test1.AddArgument("DUMMYprocess");
//   test1.AddArgument("--runtime");
//   test1.AddArgument("2");
//   test1.AddArgument("--nocrash");
//
//   maidsafe::Process test2;
//   ASSERT_TRUE(test2.SetProcessName("DUMMYprocess"));
//   test2.AddArgument("DUMMYprocess");
//   test2.AddArgument("--runtime");
//   test2.AddArgument("2");
//   test2.AddArgument("--nocrash");
//
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   uint32_t num = manager.AddProcess(test);
//   uint32_t num1 = manager.AddProcess(test1);
//   uint32_t num2 = manager.AddProcess(test2);
//   auto start(boost::posix_time::microsec_clock::universal_time());
//   manager.StartProcess(num);
//   manager.StartProcess(num1);
//   manager.StartProcess(num2);
//   manager.RestartProcess(num);
//   manager.RestartProcess(num1);
//   manager.RestartProcess(num2);
//   Sleep(boost::posix_time::milliseconds(2000));
//   manager.LetProcessDie(num);
//   manager.LetProcessDie(num1);
//   manager.LetProcessDie(num2);
//   manager.WaitForProcesses();
//   auto end(boost::posix_time::microsec_clock::universal_time());
//   boost::posix_time::time_duration elapsed(end - start);
//   int64_t seconds(elapsed.seconds());
//   EXPECT_GE(seconds, 2);
//   EXPECT_LE(seconds, 3);
//   EXPECT_EQ(3, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
// }
//
// TEST(ProcessManagerTest, BEH_StartManyDifferentProcesses) {
//   maidsafe::ProcessManager manager;
//   std::vector<Process> processes_5, processes_10;
//   for (int i(0); i < 5; ++i) {
//     maidsafe::Process test_5;
//     ASSERT_TRUE(test_5.SetProcessName("DUMMYprocess"));
//     test_5.AddArgument("DUMMYprocess");
//     test_5.AddArgument("--runtime");
//     test_5.AddArgument("5");
//     test_5.AddArgument("--nocrash");
//     processes_5.push_back(test_5);
//   }
//   for (int i(0); i < 5; ++i) {
//     maidsafe::Process test_10;
//     ASSERT_TRUE(test_10.SetProcessName("DUMMYprocess"));
//     test_10.AddArgument("DUMMYprocess");
//     test_10.AddArgument("--runtime");
//     test_10.AddArgument("10");
//     test_10.AddArgument("--nocrash");
//     processes_10.push_back(test_10);
//   }
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   std::vector<uint32_t> process_ids_5, process_ids_10;
//   for (size_t i(0); i < processes_5.size(); ++i) {
//     uint32_t num = manager.AddProcess(processes_5[i]);
//     EXPECT_GT(num, 0);
//     process_ids_5.push_back(num);
//     manager.StartProcess(num);
//   }
//   for (size_t i(0); i < processes_10.size(); ++i) {
//     uint32_t num = manager.AddProcess(processes_10[i]);
//     EXPECT_GT(num, 0);
//     manager.StartProcess(num);
//     process_ids_10.push_back(num);
//   }
//   EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfProcesses());
//   EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfLiveProcesses());
//
//   for (auto it(process_ids_5.begin()); it != process_ids_5.end(); ++it)
//     manager.LetProcessDie(*it);
//
//   Sleep(boost::posix_time::seconds(6));
//
//   EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfProcesses());
//   EXPECT_EQ(process_ids_10.size(), manager.NumberOfLiveProcesses());
//
//   for (auto it(process_ids_10.begin()); it != process_ids_10.end(); ++it)
//     manager.LetProcessDie(*it);
//
//   Sleep(boost::posix_time::seconds(6));
//   EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   manager.WaitForProcesses();
// }



TEST(ProcessManagerTest, BEH_StartSingleProcess) {
  maidsafe::ProcessManager manager;
  maidsafe::Process test;
  ASSERT_TRUE(test.SetProcessName("DUMMYprocess", parent_path_));
  boost::filesystem::path exec_path(parent_path_);
  exec_path  /= "DUMMYprocess";
  test.AddArgument(exec_path.string());
  test.AddArgument("--runtime");
  test.AddArgument("2");
  test.AddArgument("--nocrash");

  EXPECT_EQ(0, manager.NumberOfProcesses());
  EXPECT_EQ(0, manager.NumberOfLiveProcesses());
  EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
  std::string id = manager.AddProcess(test, 0);
  auto start(boost::posix_time::microsec_clock::universal_time());
  manager.StartProcess(id);
  EXPECT_NE(id, "");
  manager.LetProcessDie(id);
  manager.WaitForProcesses();
  auto end(boost::posix_time::microsec_clock::universal_time());
  boost::posix_time::time_duration elapsed(end - start);
  int64_t seconds(elapsed.seconds());
  EXPECT_GE(seconds, 2);
  EXPECT_LE(seconds, 3);
  EXPECT_EQ(1, manager.NumberOfProcesses());
  EXPECT_EQ(0, manager.NumberOfLiveProcesses());
  EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
}

// TEST(ProcessManagerTest, BEH_KillProcess) {
//   maidsafe::ProcessManager manager;
//   maidsafe::Process test;
//   ASSERT_TRUE(test.SetProcessName("DUMMYprocess"));
//   test.AddArgument("DUMMYprocess");
//   test.AddArgument("--runtime");
//   test.AddArgument("5");
//   test.AddArgument("--nocrash");
//
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   std::string id = manager.AddProcess(test);
//   auto start(boost::posix_time::microsec_clock::universal_time());
//   manager.StartProcess(id);
//   EXPECT_NE(id, "");
//   manager.KillProcess(id);
//   manager.WaitForProcesses();
//   auto end(boost::posix_time::microsec_clock::universal_time());
//   boost::posix_time::time_duration elapsed(end - start);
//   int64_t seconds(elapsed.seconds());
//   EXPECT_LE(seconds, 1);
//   EXPECT_EQ(1, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
// }
//
// TEST(ProcessManagerTest, BEH_StopProcess) {
//   maidsafe::ProcessManager manager;
//   maidsafe::Process test;
//   ASSERT_TRUE(test.SetProcessName("DUMMYprocess"));
//   test.AddArgument("DUMMYprocess");
//   test.AddArgument("--runtime");
//   test.AddArgument("5");
//   test.AddArgument("--nocrash");
//
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   std::string id = manager.AddProcess(test);
//   auto start(boost::posix_time::microsec_clock::universal_time());
//   manager.StartProcess(id);
//   EXPECT_NE(id, "");
//   manager.StopProcess(id);
//   manager.WaitForProcesses();
//   auto end(boost::posix_time::microsec_clock::universal_time());
//   boost::posix_time::time_duration elapsed(end - start);
//   int64_t seconds(elapsed.seconds());
//   EXPECT_LE(seconds, 1);
//   EXPECT_EQ(1, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
// }
//
// TEST(ProcessManagerTest, BEH_RestartProcess) {
//   maidsafe::ProcessManager manager;
//   maidsafe::Process test;
//   ASSERT_TRUE(test.SetProcessName("DUMMYprocess"));
//   test.AddArgument("DUMMYprocess");
//   test.AddArgument("--runtime");
//   test.AddArgument("2");
//   test.AddArgument("--nocrash");
//   /*test.AddArgument("--start");
// test.AddArgument("--chunkstore_capacity");
// test.AddArgument("0");
// test.AddArgument("--chunkstore_path");
// test.AddArgument("~/vault");*/
//
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   std::string id = manager.AddProcess(test);
//   auto start(boost::posix_time::microsec_clock::universal_time());
//   manager.StartProcess(id);
//   EXPECT_NE(id, "");
//   manager.RestartProcess(id);
//   Sleep(boost::posix_time::millisec(800));
//   manager.LetProcessDie(id);
//   manager.WaitForProcesses();
//   auto end(boost::posix_time::microsec_clock::universal_time());
//   boost::posix_time::time_duration elapsed(end - start);
//   int64_t seconds(elapsed.seconds());
//   EXPECT_GE(seconds, 2);
//   EXPECT_LE(seconds, 3);
//   EXPECT_EQ(1, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
// }



TEST(ProcessManagerTest, BEH_StartThreeProcesses) {
  maidsafe::ProcessManager manager;
  maidsafe::Process test;
  ASSERT_TRUE(test.SetProcessName("DUMMYprocess", parent_path_));
  boost::filesystem::path exec_path(parent_path_);
  exec_path  /= "DUMMYprocess";
  test.AddArgument(exec_path.string());
  test.AddArgument("--runtime");
  test.AddArgument("2");
  test.AddArgument("--nocrash");

  maidsafe::Process test1;
  ASSERT_TRUE(test1.SetProcessName("DUMMYprocess", parent_path_));
  test1.AddArgument(exec_path.string());
  test1.AddArgument("--runtime");
  test1.AddArgument("2");
  test1.AddArgument("--nocrash");

  maidsafe::Process test2;
  ASSERT_TRUE(test2.SetProcessName("DUMMYprocess", parent_path_));
  test2.AddArgument(exec_path.string());
  test2.AddArgument("--runtime");
  test2.AddArgument("2");
  test2.AddArgument("--nocrash");

  EXPECT_EQ(0, manager.NumberOfProcesses());
  EXPECT_EQ(0, manager.NumberOfLiveProcesses());
  EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
  std::string id = manager.AddProcess(test, 0);
  std::string id1 = manager.AddProcess(test1, 0);
  std::string id2 = manager.AddProcess(test2, 0);
  auto start(boost::posix_time::microsec_clock::universal_time());
  manager.StartProcess(id);
  manager.StartProcess(id1);
  manager.StartProcess(id2);
  manager.RestartProcess(id);
  manager.RestartProcess(id1);
  manager.RestartProcess(id2);
  Sleep(boost::posix_time::milliseconds(800));
  manager.LetProcessDie(id);
  manager.LetProcessDie(id1);
  manager.LetProcessDie(id2);
  manager.WaitForProcesses();
  auto end(boost::posix_time::microsec_clock::universal_time());
  boost::posix_time::time_duration elapsed(end - start);
  int64_t seconds(elapsed.seconds());
  EXPECT_GE(seconds, 2);
  EXPECT_LE(seconds, 3);
  EXPECT_EQ(3, manager.NumberOfProcesses());
  EXPECT_EQ(0, manager.NumberOfLiveProcesses());
  EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
}

TEST(ProcessManagerTest, BEH_StartManyDifferentProcesses) {
  maidsafe::ProcessManager manager;
  std::vector<Process> processes_5, processes_10;
  for (int i(0); i < 5; ++i) {
    maidsafe::Process test_5;
    ASSERT_TRUE(test_5.SetProcessName("DUMMYprocess", parent_path_));
    boost::filesystem::path exec_path(parent_path_);
    exec_path  /= "DUMMYprocess";
    test_5.AddArgument(exec_path.string());
    test_5.AddArgument("--runtime");
    test_5.AddArgument("5");
    test_5.AddArgument("--nocrash");
    processes_5.push_back(test_5);
  }
  for (int i(0); i < 5; ++i) {
    maidsafe::Process test_10;
    ASSERT_TRUE(test_10.SetProcessName("DUMMYprocess", parent_path_));
    boost::filesystem::path exec_path(parent_path_);
    exec_path  /= "DUMMYprocess";
    test_10.AddArgument(exec_path.string());
    test_10.AddArgument("--runtime");
    test_10.AddArgument("10");
    test_10.AddArgument("--nocrash");
    processes_10.push_back(test_10);
  }
  EXPECT_EQ(0, manager.NumberOfProcesses());
  EXPECT_EQ(0, manager.NumberOfLiveProcesses());
  EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
  std::vector<std::string> process_ids_5, process_ids_10;
  for (size_t i(0); i < processes_5.size(); ++i) {
    std::string id = manager.AddProcess(processes_5.at(i), 0);
    EXPECT_NE(id, "");
    process_ids_5.push_back(id);
    manager.StartProcess(id);
  }
  for (size_t i(0); i < processes_10.size(); ++i) {
    std::string id = manager.AddProcess(processes_10.at(i), 0);
    EXPECT_NE(id, "");
    manager.StartProcess(id);
    process_ids_10.push_back(id);
  }
  EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfProcesses());
  EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfLiveProcesses());

  for (auto it(process_ids_5.begin()); it != process_ids_5.end(); ++it)
    manager.LetProcessDie(*it);
  Sleep(boost::posix_time::seconds(6));

  EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfProcesses());
  EXPECT_EQ(process_ids_10.size(), manager.NumberOfLiveProcesses());

  for (auto it(process_ids_10.begin()); it != process_ids_10.end(); ++it)
    manager.LetProcessDie(*it);
  Sleep(boost::posix_time::seconds(6));
  EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfProcesses());
  EXPECT_EQ(0, manager.NumberOfLiveProcesses());
  manager.WaitForProcesses();
}

// TEST(ProcessManagerTest, FUNC_StartSingleProcessForLongTime) {
//   maidsafe::ProcessManager manager;
//   maidsafe::Process test;
//   ASSERT_TRUE(test.SetProcessName("DUMMYprocess"));
//   test.AddArgument("DUMMYprocess");
//   test.AddArgument("--runtime");
//   test.AddArgument("500");
//   test.AddArgument("--nocrash");
//
//   EXPECT_EQ(0, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
//   uint32_t num = manager.AddProcess(test);
//   auto start(boost::posix_time::microsec_clock::universal_time());
//   manager.StartProcess(num);
//   EXPECT_GT(num, 0);
//   Sleep(boost::posix_time::seconds(400));
//   /*manager.LetProcessDie(num);
// manager.WaitForProcesses();*/
//   manager.KillProcess(num);
//   auto end(boost::posix_time::microsec_clock::universal_time());
//   boost::posix_time::time_duration elapsed(end - start);
//   int64_t seconds(elapsed.seconds() + elapsed.minutes() * 60);
//   EXPECT_GE(seconds, 400);
//   EXPECT_LE(seconds, 401);
//   EXPECT_EQ(1, manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   EXPECT_EQ(0, manager.NumberOfSleepingProcesses());
// }


}  // namespace test

}  // namespace maidsafe

int main(int argc, char **argv) {
  maidsafe::log::FilterMap filter;
  fs::path full_path(argv[0]);
  parent_path_ = full_path.parent_path().string();
  filter["*"] = maidsafe::log::kInfo;
  return ExecuteMain(argc, argv, filter);
}
