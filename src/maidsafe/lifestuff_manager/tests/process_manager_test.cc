/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include <thread>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/lifestuff_manager/config.h"
#include "maidsafe/lifestuff_manager/process_manager.h"
#include "maidsafe/lifestuff_manager/utils.h"
#include "maidsafe/lifestuff_manager/tests/test_utils.h"


namespace fs = boost::filesystem;

namespace { std::string g_parent_path; }

namespace maidsafe {

namespace lifestuff_manager {

namespace test {

// TEST(ProcessManagerTest, BEH_StartSingleProcess) {
//   ProcessManager manager;
//   Process test;
//   ASSERT_TRUE(test.SetProcessName(kProcessName_));
//   test.AddArgument(kProcessName_);
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
//   ProcessManager manager;
//   Process test;
//   ASSERT_TRUE(test.SetProcessName(kProcessName_));
//   test.AddArgument(kProcessName_);
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
//   ProcessManager manager;
//   Process test;
//   ASSERT_TRUE(test.SetProcessName(kProcessName_));
//   test.AddArgument(kProcessName_);
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
//   Sleep(std::chrono::millisec(2000));
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
//   ProcessManager manager;
//   Process test;
//   ASSERT_TRUE(test.SetProcessName(kProcessName_));
//   test.AddArgument(kProcessName_);
//   test.AddArgument("--runtime");
//   test.AddArgument("2");
//   test.AddArgument("--nocrash");
//
//   Process test1;
//   ASSERT_TRUE(test1.SetProcessName(kProcessName_));
//   test1.AddArgument(kProcessName_);
//   test1.AddArgument("--runtime");
//   test1.AddArgument("2");
//   test1.AddArgument("--nocrash");
//
//   Process test2;
//   ASSERT_TRUE(test2.SetProcessName(kProcessName_));
//   test2.AddArgument(kProcessName_);
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
//   Sleep(std::chrono::milliseconds(2000));
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
//   ProcessManager manager;
//   std::vector<Process> processes_5, processes_10;
//   for (int i(0); i < 5; ++i) {
//     Process test_5;
//     ASSERT_TRUE(test_5.SetProcessName(kProcessName_));
//     test_5.AddArgument(kProcessName_);
//     test_5.AddArgument("--runtime");
//     test_5.AddArgument("5");
//     test_5.AddArgument("--nocrash");
//     processes_5.push_back(test_5);
//   }
//   for (int i(0); i < 5; ++i) {
//     Process test_10;
//     ASSERT_TRUE(test_10.SetProcessName(kProcessName_));
//     test_10.AddArgument(kProcessName_);
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
//   Sleep(std::chrono::seconds(6));
//
//   EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfProcesses());
//   EXPECT_EQ(process_ids_10.size(), manager.NumberOfLiveProcesses());
//
//   for (auto it(process_ids_10.begin()); it != process_ids_10.end(); ++it)
//     manager.LetProcessDie(*it);
//
//   Sleep(std::chrono::seconds(6));
//   EXPECT_EQ(process_ids_5.size() + process_ids_10.size(), manager.NumberOfProcesses());
//   EXPECT_EQ(0, manager.NumberOfLiveProcesses());
//   manager.WaitForProcesses();
// }

class ProcessManagerTest : public testing::Test {
 public:
  ProcessManagerTest()
      : process_manager_(),
        kProcessName_(detail::kVaultName),
        kExecutablePath_(fs::path(g_parent_path) / kProcessName_) {}

 protected:
  ProcessManager process_manager_;
  const std::string kProcessName_;
  fs::path kExecutablePath_;
};


TEST_F(ProcessManagerTest, BEH_StartSingleProcess) {
  ASSERT_EQ(0, GetNumRunningProcesses(detail::kVaultName));

  Process test;
  ASSERT_TRUE(test.SetExecutablePath(kExecutablePath_));
  test.AddArgument("--runtime");
  test.AddArgument("2");
  test.AddArgument("--nocrash");
  test.AddArgument("--nocontroller");

  EXPECT_EQ(0, process_manager_.NumberOfProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfLiveProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfSleepingProcesses());
  ProcessIndex process_index = process_manager_.AddProcess(test, 0);
  auto start(boost::posix_time::microsec_clock::universal_time());
  process_manager_.StartProcess(process_index);
  EXPECT_NE(0, process_index);
  EXPECT_EQ(1, GetNumRunningProcesses(detail::kVaultName));

  process_manager_.LetProcessDie(process_index);
  process_manager_.WaitForProcesses();
  auto end(boost::posix_time::microsec_clock::universal_time());
  boost::posix_time::time_duration elapsed(end - start);
  int64_t seconds(elapsed.seconds());
  EXPECT_GE(seconds, 2);
  EXPECT_LE(seconds, 5);
  EXPECT_EQ(1, process_manager_.NumberOfProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfLiveProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfSleepingProcesses());
  EXPECT_EQ(0, GetNumRunningProcesses(detail::kVaultName));
}

// TEST(ProcessManagerTest, BEH_KillProcess) {
//   ProcessManager manager;
//   Process test;
//   ASSERT_TRUE(test.SetProcessName(kProcessName_));
//   test.AddArgument(kProcessName_);
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
//   ProcessManager manager;
//   Process test;
//   ASSERT_TRUE(test.SetProcessName(kProcessName_));
//   test.AddArgument(kProcessName_);
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
//   ProcessManager manager;
//   Process test;
//   ASSERT_TRUE(test.SetProcessName(kProcessName_));
//   test.AddArgument(kProcessName_);
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
//   Sleep(std::chrono::millisec(800));
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

TEST_F(ProcessManagerTest, BEH_StartThreeProcesses) {
  Process test;
  ASSERT_TRUE(test.SetExecutablePath(kExecutablePath_));
  test.AddArgument("--runtime");
  test.AddArgument("2");
  test.AddArgument("--nocrash");
  test.AddArgument("--nocontroller");

  Process test1;
  ASSERT_TRUE(test1.SetExecutablePath(kExecutablePath_));
  test1.AddArgument("--runtime");
  test1.AddArgument("2");
  test1.AddArgument("--nocrash");
  test1.AddArgument("--nocontroller");

  Process test2;
  ASSERT_TRUE(test2.SetExecutablePath(kExecutablePath_));
  test2.AddArgument("--runtime");
  test2.AddArgument("2");
  test2.AddArgument("--nocrash");
  test2.AddArgument("--nocontroller");

  EXPECT_EQ(0, process_manager_.NumberOfProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfLiveProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfSleepingProcesses());
  ProcessIndex process_index = process_manager_.AddProcess(test, kLivePort);
  ProcessIndex process_index1 = process_manager_.AddProcess(test1, kLivePort);
  ProcessIndex process_index2 = process_manager_.AddProcess(test2, kLivePort);
  auto start(boost::posix_time::microsec_clock::universal_time());
  process_manager_.StartProcess(process_index);
  process_manager_.StartProcess(process_index1);
  process_manager_.StartProcess(process_index2);
  process_manager_.RestartProcess(process_index);
  process_manager_.RestartProcess(process_index1);
  process_manager_.RestartProcess(process_index2);
  Sleep(std::chrono::milliseconds(800));
  process_manager_.LetProcessDie(process_index);
  process_manager_.LetProcessDie(process_index1);
  process_manager_.LetProcessDie(process_index2);
  process_manager_.WaitForProcesses();
  auto end(boost::posix_time::microsec_clock::universal_time());
  boost::posix_time::time_duration elapsed(end - start);
  int64_t seconds(elapsed.seconds());
  EXPECT_GE(seconds, 2);
  EXPECT_LE(seconds, 5);
  EXPECT_EQ(3, process_manager_.NumberOfProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfLiveProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfSleepingProcesses());
}

TEST_F(ProcessManagerTest, BEH_StartManyDifferentProcesses) {
  std::vector<Process> processes_5, processes_10;
  for (int i(0); i < 5; ++i) {
    Process test_5;
    ASSERT_TRUE(test_5.SetExecutablePath(kExecutablePath_));
    test_5.AddArgument("--runtime");
    test_5.AddArgument("5");
    test_5.AddArgument("--nocrash");
    test_5.AddArgument("--nocontroller");
    processes_5.push_back(test_5);
  }
  for (int i(0); i < 5; ++i) {
    Process test_10;
    ASSERT_TRUE(test_10.SetExecutablePath(kExecutablePath_));
    test_10.AddArgument("--runtime");
    test_10.AddArgument("10");
    test_10.AddArgument("--nocrash");
    test_10.AddArgument("--nocontroller");
    processes_10.push_back(test_10);
  }
  EXPECT_EQ(0, process_manager_.NumberOfProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfLiveProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfSleepingProcesses());
  std::vector<ProcessIndex> process_indices_5, process_indices_10;
  for (size_t i(0); i < processes_5.size(); ++i) {
    ProcessIndex process_index = process_manager_.AddProcess(processes_5.at(i), 0);
    EXPECT_NE(0, process_index);
    process_indices_5.push_back(process_index);
    process_manager_.StartProcess(process_index);
  }
  for (size_t i(0); i < processes_10.size(); ++i) {
    ProcessIndex process_index = process_manager_.AddProcess(processes_10.at(i), 0);
    EXPECT_NE(0, process_index);
    process_manager_.StartProcess(process_index);
    process_indices_10.push_back(process_index);
  }
  EXPECT_EQ(process_indices_5.size() + process_indices_10.size(),
            process_manager_.NumberOfProcesses());
  EXPECT_EQ(process_indices_5.size() + process_indices_10.size(),
            process_manager_.NumberOfLiveProcesses());

  for (auto it(process_indices_5.begin()); it != process_indices_5.end(); ++it)
    process_manager_.LetProcessDie(*it);
  Sleep(std::chrono::seconds(6));

  EXPECT_EQ(process_indices_5.size() + process_indices_10.size(),
            process_manager_.NumberOfProcesses());
  EXPECT_EQ(process_indices_10.size(), process_manager_.NumberOfLiveProcesses());

  for (auto it(process_indices_10.begin()); it != process_indices_10.end(); ++it)
    process_manager_.LetProcessDie(*it);
  Sleep(std::chrono::seconds(6));
  EXPECT_EQ(process_indices_5.size() + process_indices_10.size(),
            process_manager_.NumberOfProcesses());
  EXPECT_EQ(0, process_manager_.NumberOfLiveProcesses());
  process_manager_.WaitForProcesses();
}

// TEST(ProcessManagerTest, FUNC_StartSingleProcessForLongTime) {
//   ProcessManager manager;
//   Process test;
//   ASSERT_TRUE(test.SetProcessName(kProcessName_));
//   test.AddArgument(kProcessName_);
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
//   Sleep(std::chrono::seconds(400));
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

}  // namespace lifestuff_manager

}  // namespace maidsafe


int main(int argc, char **argv) {
  fs::path full_path(argv[0]);
  g_parent_path = full_path.parent_path().string();
  return maidsafe::test::ExecuteMain(argc, argv);
}
