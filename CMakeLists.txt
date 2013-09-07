#==================================================================================================#
#                                                                                                  #
#  Copyright 2012 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or    #
#  later, and The General Public License (GPL), version 3. By contributing code to this project    #
#  You agree to the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in    #
#  the root directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also    #
#  available at:                                                                                   #
#                                                                                                  #
#    http://www.novinet.com/license                                                                #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, software distributed under the       #
#  License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,       #
#  either express or implied. See the License for the specific language governing permissions      #
#  and limitations under the License.                                                              #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.10 FATAL_ERROR)
project(private)

include(../../cmake_modules/standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${passport_SOURCE_DIR}/include)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(LifestuffManagerSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff_manager)
glob_dir(LifestuffManager ${LifestuffManagerSourcesDir} "LifeStuff Manager")
set(LifestuffManagerCoreAllFiles
      "${LifestuffManagerSourcesDir}/lifestuff_manager.cc"
      "${LifestuffManagerSourcesDir}/lifestuff_manager.h"
      "${LifestuffManagerSourcesDir}/config.h"
      ${LifestuffManagerProtoHeaders})
source_group("LifeStuff Manager Core Source Files" FILES "${LifestuffManagerSourcesDir}/lifestuff_manager.cc")
source_group("LifeStuff Manager Core Header Files" FILES "${LifestuffManagerSourcesDir}/lifestuff_manager.h"
                                                         "${LifestuffManagerSourcesDir}/config.h")
list(REMOVE_ITEM LifestuffManagerAllFiles
       ${LifestuffManagerCoreAllFiles}
       "${LifestuffManagerSourcesDir}/lifestuff_manager_main.cc")

glob_dir(DataTypes ${PROJECT_SOURCE_DIR}/src/maidsafe/data_types "Data Types")
glob_dir(DataStore ${PROJECT_SOURCE_DIR}/src/maidsafe/data_store "Data Store")

# Tests
glob_dir(LifestuffManagerTests ${LifestuffManagerSourcesDir}/tests "LifeStuff Manager Tests")
list(REMOVE_ITEM LifestuffManagerTestsAllFiles
       "${LifestuffManagerSourcesDir}/tests/dummy_client.cc"
       "${LifestuffManagerSourcesDir}/tests/dummy_vault.cc")

glob_dir(DataTypesTests ${PROJECT_SOURCE_DIR}/src/maidsafe/data_types/tests "Data Types Tests")
glob_dir(DataStoreTests ${PROJECT_SOURCE_DIR}/src/maidsafe/data_store/tests "Data Store Tests")


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(private ${DataStoreAllFiles} ${DataTypesAllFiles})
ms_add_static_library(lifestuff_manager ${LifestuffManagerAllFiles})
ms_add_static_library(lifestuff_manager_core
    ${LifestuffManagerCoreAllFiles}
    "${CMAKE_BINARY_DIR}/GeneratedProtoFiles/maidsafe/lifestuff_manager/vault_info.pb.h")
ms_add_static_library(lifestuff_manager_core_dummy ${LifestuffManagerCoreAllFiles})

ms_add_executable(lifestuff_mgr "Production" "${LifestuffManagerSourcesDir}/lifestuff_manager_main.cc")
ms_add_executable(signing_tool "Tools" "${PROJECT_SOURCE_DIR}/src/maidsafe/tools/signing_tool.cc")
ms_add_executable(bootstrap_file_tool "Tools"
    "${PROJECT_SOURCE_DIR}/src/maidsafe/tools/bootstrap_file_tool.cc"
    "${CMAKE_BINARY_DIR}/GeneratedProtoFiles/maidsafe/lifestuff_manager/vault_info.pb.cc"
    "${CMAKE_BINARY_DIR}/GeneratedProtoFiles/maidsafe/lifestuff_manager/vault_info.pb.h"
    "${PROJECT_SOURCE_DIR}/src/maidsafe/lifestuff_manager/vault_info.proto")
if(MaidsafeTesting)
  ms_add_executable(TESTprivate "Tests/Private" ${DataStoreTestsAllFiles} ${DataTypesTestsAllFiles})
  ms_add_executable(TESTlifestuff_manager "Tests/Private" ${LifestuffManagerTestsAllFiles})
  ms_add_executable(dummy_client "Tests/Private" "${LifestuffManagerSourcesDir}/tests/dummy_client.cc")
  ms_add_executable(dummy_vault "Tests/Private" "${LifestuffManagerSourcesDir}/tests/dummy_vault.cc")
  ms_add_executable(client_controller_tool "Tools" "${PROJECT_SOURCE_DIR}/src/maidsafe/tools/client_controller_tool.cc")
endif()

target_link_libraries(maidsafe_private maidsafe_passport maidsafe_common)
target_link_libraries(maidsafe_lifestuff_manager maidsafe_passport ${BoostRegexLibs})
add_dependencies(maidsafe_lifestuff_manager_core boost_process)
add_dependencies(maidsafe_lifestuff_manager_core_dummy boost_process)
target_link_libraries(lifestuff_mgr maidsafe_lifestuff_manager_core maidsafe_lifestuff_manager)
target_link_libraries(signing_tool maidsafe_passport)
target_link_libraries(bootstrap_file_tool maidsafe_common)
if(MaidsafeTesting)
  target_link_libraries(TESTprivate maidsafe_private)
  target_link_libraries(TESTlifestuff_manager maidsafe_lifestuff_manager maidsafe_lifestuff_manager_core_dummy maidsafe_passport)
  target_link_libraries(dummy_client maidsafe_lifestuff_manager)
  target_link_libraries(dummy_vault maidsafe_lifestuff_manager ${BoostRegexLibs})
  target_link_libraries(client_controller_tool maidsafe_lifestuff_manager maidsafe_lifestuff_manager_core_dummy maidsafe_passport)

  add_dependencies(TESTlifestuff_manager dummy_vault)
endif()


rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)
remove_definitions(-DAPPLICATION_NAME=LifeStuff)
set_target_properties(maidsafe_private
                      maidsafe_lifestuff_manager
                      maidsafe_lifestuff_manager_core
                      lifestuff_mgr
                      bootstrap_file_tool PROPERTIES COMPILE_DEFINITIONS APPLICATION_NAME=LifeStuff)
set_target_properties(maidsafe_lifestuff_manager_core_dummy PROPERTIES COMPILE_DEFINITIONS "USE_DUMMY_VAULT;APPLICATION_NAME=LifeStuff")
set_target_properties(signing_tool PROPERTIES COMPILE_DEFINITIONS APPLICATION_NAME=SigningTool)

if(MaidsafeTesting)
  if(MSVC)
    # TODO - Investigate why boost variant requires this warning to be disabled in RelWithDebInfo only.
    set_target_properties(TESTprivate PROPERTIES COMPILE_FLAGS "/bigobj /wd4702")
  endif()
  set_target_properties(TESTprivate
                        dummy_client
                        dummy_vault
                        client_controller_tool PROPERTIES COMPILE_DEFINITIONS APPLICATION_NAME=LifeStuff)
  set_target_properties(TESTlifestuff_manager PROPERTIES COMPILE_DEFINITIONS "USE_DUMMY_VAULT;APPLICATION_NAME=LifeStuff")
endif()


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  add_style_test()
  add_gtests(TESTlifestuff_manager)
  add_gtests(TESTprivate)
  add_project_experimental()
  test_summary_output()
endif()
