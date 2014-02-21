#==================================================================================================#
#                                                                                                  #
#  Copyright 2012 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,        #
#  version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which    #
#  licence you accepted on initial access to the Software (the "Licences").                        #
#                                                                                                  #
#  By contributing code to the MaidSafe Software, or to this project generally, you agree to be    #
#  bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root        #
#  directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available   #
#  at: http://www.maidsafe.net/licenses                                                            #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed    #
#  under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF   #
#  ANY KIND, either express or implied.                                                            #
#                                                                                                  #
#  See the Licences for the specific language governing permissions and limitations relating to    #
#  use of the MaidSafe Software.                                                                   #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_modules/standard_setup.cmake")
  cmake_minimum_required(VERSION 2.8)  # To suppress warning cluttering error message
  set(Msg "\nThis project can currently only be build as part of the MaidSafe super-project.  For")
  set(Msg "${Msg} full details, see https://github.com/maidsafe/MaidSafe/wiki/Build-Instructions\n")
  message(FATAL_ERROR "${Msg}")
endif()

project(private)

include(../../cmake_modules/standard_setup.cmake)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(ClientManagerSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe/client_manager)
ms_glob_dir(ClientManager ${ClientManagerSourcesDir} "Client Manager")
set(ClientManagerCoreAllFiles
      "${ClientManagerSourcesDir}/client_manager.cc"
      "${ClientManagerSourcesDir}/client_manager.h"
      "${ClientManagerSourcesDir}/config.h"
      ${ClientManagerProtoHeaders})
source_group("Client Manager Core Source Files" FILES "${ClientManagerSourcesDir}/client_manager.cc")
source_group("Client Manager Core Header Files" FILES "${ClientManagerSourcesDir}/client_manager.h"
                                                         "${ClientManagerSourcesDir}/config.h")
list(REMOVE_ITEM ClientManagerAllFiles
       ${ClientManagerCoreAllFiles}
       "${ClientManagerSourcesDir}/client_manager_main.cc")

###ms_glob_dir(DataTypes ${PROJECT_SOURCE_DIR}/src/maidsafe/data_types "Data Types")
###ms_glob_dir(DataStore ${PROJECT_SOURCE_DIR}/src/maidsafe/data_store "Data Store")

# Tests
ms_glob_dir(ClientManagerTests ${ClientManagerSourcesDir}/tests "Client Manager Tests")
list(REMOVE_ITEM ClientManagerTestsAllFiles
       "${ClientManagerSourcesDir}/tests/dummy_client.cc"
       "${ClientManagerSourcesDir}/tests/dummy_vault.cc")

###file(GLOB DataTypesTestsSources ${PROJECT_SOURCE_DIR}/src/maidsafe/data_types/tests/*.cc)
###file(GLOB DataStoreTestsSources ${PROJECT_SOURCE_DIR}/src/maidsafe/data_store/tests/*.cc)
###set(TestsMain ${PROJECT_SOURCE_DIR}/src/maidsafe/data_types/tests/tests_main.cc)
###list(REMOVE_ITEM DataTypesTestsSources ${TestsMain})


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
###ms_add_static_library(maidsafe_private ${DataStoreAllFiles} ${DataTypesAllFiles})
ms_add_static_library(maidsafe_client_manager ${ClientManagerAllFiles})
ms_add_static_library(maidsafe_client_manager_core
    ${ClientManagerCoreAllFiles}
    "${CMAKE_BINARY_DIR}/GeneratedProtoFiles/maidsafe/client_manager/vault_info.pb.h")
ms_add_static_library(maidsafe_client_manager_core_dummy ${ClientManagerCoreAllFiles})
###target_include_directories(maidsafe_private PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(maidsafe_client_manager PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(maidsafe_client_manager_core PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_include_directories(maidsafe_client_manager_core_dummy PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)

set(client_mgrName ClientManager)
ms_add_executable(client_mgr "Production" "${ClientManagerSourcesDir}/client_manager_main.cc")
target_include_directories(client_mgr PRIVATE ${PROJECT_SOURCE_DIR}/src)
###ms_add_executable(signing_tool "Tools/Private" "${PROJECT_SOURCE_DIR}/src/maidsafe/tools/signing_tool.cc")
###ms_add_executable(bootstrap_file_tool "Tools/Private"
###    "${PROJECT_SOURCE_DIR}/src/maidsafe/tools/bootstrap_file_tool.cc"
###    "${CMAKE_BINARY_DIR}/GeneratedProtoFiles/maidsafe/client_manager/vault_info.pb.cc"
###    "${CMAKE_BINARY_DIR}/GeneratedProtoFiles/maidsafe/client_manager/vault_info.pb.h"
###    "${PROJECT_SOURCE_DIR}/src/maidsafe/client_manager/vault_info.proto")

###target_link_libraries(maidsafe_private maidsafe_passport maidsafe_common)
target_link_libraries(maidsafe_client_manager maidsafe_passport ${BoostRegexLibs})
target_link_libraries(maidsafe_client_manager_core maidsafe_passport)
target_link_libraries(maidsafe_client_manager_core_dummy maidsafe_passport)
add_dependencies(maidsafe_client_manager_core boost_process)
add_dependencies(maidsafe_client_manager_core_dummy boost_process)
target_link_libraries(client_mgr maidsafe_client_manager_core maidsafe_client_manager)
###target_link_libraries(signing_tool maidsafe_passport)
###target_link_libraries(bootstrap_file_tool maidsafe_common)

ms_rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)
target_compile_definitions(maidsafe_client_manager PRIVATE COMPANY_NAME=MaidSafe APPLICATION_NAME=ClientManager)
target_compile_definitions(maidsafe_client_manager_core PRIVATE COMPANY_NAME=MaidSafe APPLICATION_NAME=ClientManager)
target_compile_definitions(maidsafe_client_manager_core_dummy PRIVATE COMPANY_NAME=MaidSafe APPLICATION_NAME=ClientManager USE_DUMMY_VAULT)


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  ms_add_executable(TESTclient_manager "Tests/Private" ${ClientManagerTestsAllFiles})
  target_include_directories(TESTclient_manager PRIVATE ${PROJECT_SOURCE_DIR}/src)
  ms_add_executable(dummy_client "Tests/Private" "${ClientManagerSourcesDir}/tests/dummy_client.cc")
  ms_add_executable(dummy_vault "Tests/Private" "${ClientManagerSourcesDir}/tests/dummy_vault.cc")
  ms_add_executable(client_controller_tool "Tools/Private" "${PROJECT_SOURCE_DIR}/src/maidsafe/tools/client_controller_tool.cc")
  target_include_directories(client_controller_tool PRIVATE ${PROJECT_SOURCE_DIR}/src)

  target_link_libraries(TESTclient_manager maidsafe_client_manager maidsafe_client_manager_core_dummy maidsafe_passport)
  target_link_libraries(dummy_client maidsafe_client_manager)
  target_link_libraries(dummy_vault maidsafe_client_manager ${BoostRegexLibs})
  target_link_libraries(client_controller_tool maidsafe_client_manager maidsafe_client_manager_core_dummy maidsafe_passport)

  add_dependencies(TESTclient_manager dummy_vault)

  target_compile_definitions(TESTclient_manager PRIVATE USE_DUMMY_VAULT)

###  macro(PrivateTests Group)
###    foreach(TestSource ${ARGN})
###      get_filename_component(Exe ${TestSource} NAME_WE)
###      string(REGEX REPLACE "(.*)_test" "test_\\1" Exe ${Exe})
###      set(TestSources ${TestSource} ${TestsMain})
###      ms_add_executable(${Exe} "Tests/Private/${Group}" ${TestSources})
###      target_link_libraries(${Exe} maidsafe_private)
###      # TODO - Investigate why boost variant requires this warning to be disabled in RelWithDebInfo only.
###      target_compile_options(${Exe} PRIVATE $<$<BOOL:${MSVC}>:/bigobj $<$<CONFIG:RelWithDebInfo>:/wd4702>>)
###      ms_add_catch_tests(${Exe})
###    endforeach()
###  endmacro()

###  PrivateTests("Data Store Tests" ${DataStoreTestsSources})
###  PrivateTests("Data Types Tests" ${DataTypesTestsSources})

  ms_add_style_test()
  ms_add_gtests(TESTclient_manager)
  ms_add_project_experimental()
  ms_test_summary_output()
endif()
