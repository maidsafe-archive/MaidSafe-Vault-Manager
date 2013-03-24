#==================================================================================================#
#                                                                                                  #
#  Copyright (c) 2012 MaidSafe.net limited                                                         #
#                                                                                                  #
#  The following source code is property of MaidSafe.net limited and is not meant for external     #
#  use.  The use of this code is governed by the license file licence.txt found in the root        #
#  directory of this project and also on www.maidsafe.net.                                         #
#                                                                                                  #
#  You are not free to copy, amend or otherwise use this source code without the explicit written  #
#  permission of the board of directors of MaidSafe.net.                                           #
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
set(LifestuffManagerMain ${LifestuffManagerSourcesDir}/lifestuff_manager_main.cc)
set(LifestuffManagerCC ${LifestuffManagerSourcesDir}/lifestuff_manager.cc)
set(LifestuffManagerH ${LifestuffManagerSourcesDir}/lifestuff_manager.h)
set(LifestuffManagerConfig ${LifestuffManagerSourcesDir}/config.h)
set(LifestuffManagerCoreFiles ${LifestuffManagerCC} ${LifestuffManagerH} ${LifestuffManagerConfig})
list(REMOVE_ITEM LifestuffManagerAllFiles ${LifestuffManagerMain} ${LifestuffManagerCoreFiles})
source_group("LifeStuff Manager Core Source Files" FILES ${LifestuffManagerCC})
source_group("LifeStuff Manager Core Header Files" FILES ${LifestuffManagerH} ${LifestuffManagerConfig})

glob_dir(DataTypes ${PROJECT_SOURCE_DIR}/src/maidsafe/data_types "Data Types\\\\")

glob_dir(DataStore ${PROJECT_SOURCE_DIR}/src/maidsafe/data_store "Data Store\\\\")

glob_dir(LifestuffManagerTests ${LifestuffManagerSourcesDir}/tests "LifeStuff Manager Tests")
list(REMOVE_ITEM LifestuffManagerTestsAllFiles ${LifestuffManagerSourcesDir}/tests/dummy_client.cc)
list(REMOVE_ITEM LifestuffManagerTestsAllFiles ${LifestuffManagerSourcesDir}/tests/dummy_vault.cc)

glob_dir(DataTypesTests ${PROJECT_SOURCE_DIR}/src/maidsafe/data_types/tests "Data Types Tests")

glob_dir(DataStoreTests ${PROJECT_SOURCE_DIR}/src/maidsafe/data_store/tests "Data Store Tests")


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(lifestuff_manager ${LifestuffManagerAllFiles})
ms_add_static_library(lifestuff_manager_core ${LifestuffManagerCoreFiles})
ms_add_static_library(lifestuff_manager_core_dummy ${LifestuffManagerCoreFiles})
ms_add_static_library(private ${DataTypesAllFiles} ${DataStoreAllFiles})

ms_add_executable(lifestuff_mgr "Production" ${LifestuffManagerSourcesDir}/lifestuff_manager_main.cc)
ms_add_executable(signing_tool "Tools" ${PROJECT_SOURCE_DIR}/src/maidsafe/tools/signing_tool.cc)
ms_add_executable(bootstrap_file_tool "Tools" ${PROJECT_SOURCE_DIR}/src/maidsafe/tools/bootstrap_file_tool.cc
                                              ${LifestuffManagerSourcesDir}/vault_info.pb.cc
                                              ${LifestuffManagerSourcesDir}/vault_info.pb.h
                                              ${LifestuffManagerSourcesDir}/vault_info.proto)
if(MaidsafeTesting)
  ms_add_executable(TESTlifestuff_manager "Tests/Private" ${LifestuffManagerTestsAllFiles})
  ms_add_executable(dummy_client "Tests/Private" ${LifestuffManagerSourcesDir}/tests/dummy_client.cc)
  ms_add_executable(dummy_vault "Tests/Private" ${LifestuffManagerSourcesDir}/tests/dummy_vault.cc)
  ms_add_executable(TESTprivate "Tests/Private" ${DataTypesTestsAllFiles} ${DataStoreTestsAllFiles})
endif()

target_link_libraries(maidsafe_private maidsafe_passport maidsafe_common)
target_link_libraries(maidsafe_lifestuff_manager maidsafe_passport ${BoostRegexLibs})
target_link_libraries(signing_tool maidsafe_passport)
target_link_libraries(bootstrap_file_tool maidsafe_common)
target_link_libraries(lifestuff_mgr maidsafe_lifestuff_manager_core maidsafe_lifestuff_manager)
if(MaidsafeTesting)
  target_link_libraries(TESTprivate maidsafe_private)
  target_link_libraries(dummy_vault maidsafe_lifestuff_manager ${BoostRegexLibs})
  target_link_libraries(dummy_client maidsafe_lifestuff_manager)
  target_link_libraries(TESTlifestuff_manager maidsafe_lifestuff_manager maidsafe_lifestuff_manager_core_dummy maidsafe_passport)

  add_dependencies(TESTlifestuff_manager dummy_vault)
endif()

rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)

if(MaidsafeTesting)
  if(MSVC)
    # TODO - Investigate why boost variant requires this warning to be disabled in RelWithDebInfo only.
    set_target_properties(TESTprivate PROPERTIES COMPILE_FLAGS "/wd4702")
  endif()
  set_target_properties(maidsafe_lifestuff_manager_core_dummy TESTlifestuff_manager PROPERTIES COMPILE_DEFINITIONS "USE_DUMMY_VAULT")
endif()

if(UNIX)
  set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wno-effc++")
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
