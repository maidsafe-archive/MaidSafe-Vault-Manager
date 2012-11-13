#==============================================================================#
#                                                                              #
#  Copyright (c) 2012 MaidSafe.net limited                                     #
#                                                                              #
#  The following source code is property of MaidSafe.net limited and is not    #
#  meant for external use.  The use of this code is governed by the license    #
#  file licence.txt found in the root directory of this project and also on    #
#  www.maidsafe.net.                                                           #
#                                                                              #
#  You are not free to copy, amend or otherwise use this source code without   #
#  the explicit written permission of the board of directors of MaidSafe.net.  #
#                                                                              #
#==============================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)
project(private)

set(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
file(GLOB_RECURSE PROTO_FILES RELATIVE ${PROTO_SOURCE_DIR} "${PROTO_SOURCE_DIR}/maidsafe/*.proto")
include(../../cmake_modules/maidsafe_standard_setup.cmake)

if(EXISTS "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/appendable_by_all.pb.h")
  file(RENAME "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/appendable_by_all.pb.h"
              "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_actions/appendable_by_all.pb.h")
endif()
if(EXISTS "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/chunk.pb.h")
  file(RENAME "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/chunk.pb.h"
              "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_actions/chunk.pb.h")
endif()

include_directories(${common_SOURCE_DIR}/include)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
file(GLOB SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/*.cc")
list(REMOVE_ITEM SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/lifestuff_manager_main.cc")
list(REMOVE_ITEM SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/lifestuff_manager.cc")
file(GLOB HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/*.h")
list(REMOVE_ITEM HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/lifestuff_manager.h")
list(REMOVE_ITEM HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/config.h")
file(GLOB API_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/lifestuff_manager/*.h")

file(GLOB PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/*.proto")
file(GLOB SOURCE_PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/*.pb.cc")
file(GLOB HEADER_PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/*.pb.h")
file(GLOB MS_HEADER_PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/*_pb.h")

set(ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR ${SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR}
                                             ${HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR}
                                             ${PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR}
                                             ${API_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})
set(ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_CORE "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/lifestuff_manager.cc"
                                             "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/lifestuff_manager.h"
                                             "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/config.h")
list(REMOVE_ITEM SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR ${SOURCE_PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})
list(REMOVE_ITEM HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR ${HEADER_PROTO_FILES_LIFESTUFF_MANAGER_PRIVATE_DIR}
                                                            ${MS_HEADER_PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})
set(STYLE_CHECK_FILES ${SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR}
                      ${HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR}
                      ${API_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})
list(REMOVE_ITEM STYLE_CHECK_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/controller_messages.pb.h"
                                   "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/vault_info.pb.h")

source_group("LifeStuff Manager Source Files" FILES ${SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})
source_group("LifeStuff Manager Header Files" FILES ${HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})
source_group("LifeStuff Manager Core Source Files" FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/lifestuff_manager.cc"})
source_group("LifeStuff Manager Core Header Files" FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/lifestuff_manager.h"
                                                         "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/config.h")
source_group("LifeStuff Manager Proto Files" FILES ${PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR}
                                                   ${SOURCE_PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR}
                                                   ${HEADER_PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR}
                                                   ${MS_HEADER_PROTO_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})
source_group("LifeStuff Manager API Files" FILES ${API_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})


file(GLOB SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/*.cc")
file(GLOB HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/*.h")
file(GLOB API_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_actions/*.h")

file(GLOB PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/*.proto")
file(GLOB SOURCE_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/*.pb.cc")
file(GLOB HEADER_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_actions/*.pb.h")
file(GLOB MS_HEADER_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_actions/*_pb.h")

set(ALL_FILES_PRIVATE_CHUNK_ACTIONS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${API_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
list(REMOVE_ITEM SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR ${SOURCE_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
list(REMOVE_ITEM API_FILES_PRIVATE_CHUNK_ACTIONS_DIR ${HEADER_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${MS_HEADER_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
set(STYLE_CHECK_FILES ${STYLE_CHECK_FILES} ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${API_FILES_PRIVATE_CHUNK_ACTIONS_DIR})

source_group("Chunk Actions Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
source_group("Chunk Actions Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
source_group("Chunk Actions Proto Files" FILES ${PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${SOURCE_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${HEADER_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${MS_HEADER_PROTO_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
source_group("Chunk Actions API Files" FILES ${API_FILES_PRIVATE_CHUNK_ACTIONS_DIR})


file(GLOB SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/*.cc")
file(GLOB HEADER_FILES_PRIVATE_CHUNK_STORE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/*.h")
file(GLOB API_FILES_PRIVATE_CHUNK_STORE_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_store/*.h")
set(ALL_FILES_PRIVATE_CHUNK_STORE_DIR ${SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR} ${HEADER_FILES_PRIVATE_CHUNK_STORE_DIR} ${API_FILES_PRIVATE_CHUNK_STORE_DIR})
set(STYLE_CHECK_FILES ${STYLE_CHECK_FILES} ${ALL_FILES_PRIVATE_CHUNK_STORE_DIR})
source_group("Chunk Store Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR})
source_group("Chunk Store Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_STORE_DIR})
source_group("Chunk Store API Files" FILES ${API_FILES_PRIVATE_CHUNK_STORE_DIR})


file(GLOB SOURCE_FILES_PRIVATE_UTILS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/utils/*.cc")
file(GLOB HEADER_FILES_PRIVATE_UTILS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/utils/*.h")
file(GLOB API_FILES_PRIVATE_UTILS_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/utils/*.h")
set(ALL_FILES_PRIVATE_UTILS_DIR ${SOURCE_FILES_PRIVATE_UTILS_DIR} ${HEADER_FILES_PRIVATE_UTILS_DIR} ${API_FILES_PRIVATE_UTILS_DIR})
set(STYLE_CHECK_FILES ${STYLE_CHECK_FILES} ${ALL_FILES_PRIVATE_UTILS_DIR})
list(REMOVE_ITEM STYLE_CHECK_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/private/utils/fob.pb.cc")
list(REMOVE_ITEM STYLE_CHECK_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/private/utils/fob.pb.h")
source_group("Utilities Source Files" FILES ${SOURCE_FILES_PRIVATE_UTILS_DIR})
source_group("Utilities Header Files" FILES ${HEADER_FILES_PRIVATE_UTILS_DIR})
source_group("Utilities API Files" FILES ${API_FILES_PRIVATE_UTILS_DIR})

set(RETURN_CODES_H "${PROJECT_SOURCE_DIR}/include/maidsafe/private/return_codes.h")
source_group("Private API Files" FILES ${RETURN_CODES_H})


####    TESTS    ####
file(GLOB SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/tests/*.cc")
file(GLOB HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/tests/*.h")
set(ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR ${SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR} ${HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR})
set(STYLE_CHECK_FILES ${STYLE_CHECK_FILES} ${ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR})
source_group("LifeStuff Manager Tests Source Files" FILES ${SOURCE_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR})
source_group("LifeStuff Manager Tests Header Files" FILES ${HEADER_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR})
list(REMOVE_ITEM ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/tests/dummy_client.cc")
list(REMOVE_ITEM ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/tests/dummy_vault.cc")

file(GLOB SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/tests/*.cc")
file(GLOB HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/tests/*.h")
set(ALL_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})
set(STYLE_CHECK_FILES ${STYLE_CHECK_FILES} ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})
source_group("Chunk Actions Tests Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})
source_group("Chunk Actions Tests Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})

file(GLOB SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/*.cc")
file(GLOB HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/*.h")
set(ALL_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
set(STYLE_CHECK_FILES ${STYLE_CHECK_FILES} ${ALL_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
source_group("Chunk Store Tests Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
source_group("Chunk Store Tests Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})

file(GLOB SOURCE_FILES_UTILS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/utils/tests/*.cc")
file(GLOB HEADER_FILES_UTILS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/utils/tests/*.h")
set(ALL_FILES_PRIVATE_UTILS_TESTS_DIR ${SOURCE_FILES_UTILS_TESTS_DIR} ${HEADER_FILES_UTILS_TESTS_DIR})
set(STYLE_CHECK_FILES ${STYLE_CHECK_FILES} ${ALL_FILES_PRIVATE_UTILS_TESTS_DIR})
source_group("Utils Tests Source Files" FILES ${SOURCE_FILES_UTILS_TESTS_DIR})
source_group("Utils Tests Header Files" FILES ${HEADER_FILES_UTILS_TESTS_DIR})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(lifestuff_manager ${ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_DIR})
ms_add_static_library(lifestuff_manager_core ${ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_CORE})
ms_add_static_library(lifestuff_manager_core_dummy ${ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_CORE})
ms_add_static_library(private ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${ALL_FILES_PRIVATE_CHUNK_STORE_DIR} ${RETURN_CODES_H})
ms_add_static_library(utilities ${ALL_FILES_PRIVATE_UTILS_DIR})

ms_add_executable(lifestuff_mgr "Production" "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/lifestuff_manager_main.cc")
ms_add_executable(signing_tool "Tools" "${PROJECT_SOURCE_DIR}/src/maidsafe/private/tools/signing_tool.cc")
if(MAIDSAFE_TESTING)
  ms_add_executable(TESTlifestuff_manager "Tests/Private" ${ALL_FILES_PRIVATE_LIFESTUFF_MANAGER_TESTS_DIR})
  ms_add_executable(dummy_client "Tests/Private" "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/tests/dummy_client.cc")
  ms_add_executable(dummy_vault "Tests/Private" "${PROJECT_SOURCE_DIR}/src/maidsafe/private/lifestuff_manager/tests/dummy_vault.cc")
  ms_add_executable(TESTprivate "Tests/Private" ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR} ${ALL_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
  ms_add_executable(TESTutilities "Tests/Private" ${ALL_FILES_PRIVATE_UTILS_TESTS_DIR})
endif()

target_link_libraries(maidsafe_lifestuff_manager maidsafe_utilities)
target_link_libraries(maidsafe_private maidsafe_utilities)
target_link_libraries(maidsafe_utilities maidsafe_common)
target_link_libraries(signing_tool maidsafe_private)
target_link_libraries(lifestuff_mgr maidsafe_lifestuff_manager maidsafe_lifestuff_manager_core)
if(MAIDSAFE_TESTING)
  target_link_libraries(TESTprivate maidsafe_private)
  target_link_libraries(TESTutilities maidsafe_utilities)
  target_link_libraries(dummy_vault maidsafe_lifestuff_manager)
  target_link_libraries(dummy_client maidsafe_lifestuff_manager)
  target_link_libraries(TESTlifestuff_manager maidsafe_lifestuff_manager maidsafe_lifestuff_manager_core_dummy)

  add_dependencies(TESTlifestuff_manager dummy_vault)
endif()


rename_outdated_built_exes()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)

if(MAIDSAFE_TESTING)
  set_target_properties(maidsafe_lifestuff_manager_core_dummy TESTlifestuff_manager PROPERTIES COMPILE_DEFINITIONS "USE_DUMMY_VAULT")
endif()

file(GLOB_RECURSE PROTO_SOURCE_FILES "${PROTO_SOURCE_DIR}/maidsafe/*.pb.cc")
file(GLOB_RECURSE PROTO_HEADER_FILES "${PROJECT_SOURCE_DIR}/include/maidsafe/*.pb.h")
ms_disable_warnings(${PROTO_SOURCE_FILES})
if(UNIX)
  set_source_files_properties("${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/mock_chunk_manager.cc"
                              "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/mock_chunk_manager.h"
                               PROPERTIES COMPILE_FLAGS "-Wno-effc++")
  set_source_files_properties("${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/threadsafe_chunk_store_test.cc"
                              PROPERTIES COMPILE_FLAGS "-Wstrict-overflow=2")
endif()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
if(MAIDSAFE_TESTING)
  add_style_test(${STYLE_CHECK_FILES})
  add_gtests(TESTlifestuff_manager)
  add_gtests(TESTprivate)
  add_gtests(TESTutilities)
  add_project_experimental()
  test_summary_output()
endif()
