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
if(${RAN_PROTOC})
  file(RENAME "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/appendable_by_all.pb.h"
              "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_actions/appendable_by_all.pb.h")
  file(RENAME "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/chunk.pb.h"
              "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_actions/chunk.pb.h")
endif()

include_directories(${common_SOURCE_DIR}/include)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
file(GLOB SOURCE_FILES_PRIVATE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/*.cc")
file(GLOB HEADER_FILES_PRIVATE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/*.h")
file(GLOB API_FILES_PRIVATE_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/*.h")
set(ALL_FILES_PRIVATE_DIR ${SOURCE_FILES_PRIVATE_DIR} ${HEADER_FILES_PRIVATE_DIR} ${API_FILES_PRIVATE_DIR})
source_group("Private Source Files" FILES ${SOURCE_FILES_PRIVATE_DIR})
source_group("Private Header Files" FILES ${HEADER_FILES_PRIVATE_DIR})
source_group("Private API Files" FILES ${API_FILES_PRIVATE_DIR})

file(GLOB SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/*.cc")
file(GLOB HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/*.h")
file(GLOB API_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_actions/*.h")
set(ALL_FILES_PRIVATE_CHUNK_ACTIONS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${API_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
source_group("Chunk Actions Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
source_group("Chunk Actions Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
source_group("Chunk Actions API Files" FILES ${API_FILES_PRIVATE_CHUNK_ACTIONS_DIR})

file(GLOB SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/*.cc")
file(GLOB HEADER_FILES_PRIVATE_CHUNK_STORE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/*.h")
file(GLOB API_FILES_PRIVATE_CHUNK_STORE_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/private/chunk_store/*.h")
set(ALL_FILES_PRIVATE_CHUNK_STORE_DIR ${SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR} ${HEADER_FILES_PRIVATE_CHUNK_STORE_DIR} ${API_FILES_PRIVATE_CHUNK_STORE_DIR})
source_group("Chunk Store Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR})
source_group("Chunk Store Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_STORE_DIR})
source_group("Chunk Store API Files" FILES ${API_FILES_PRIVATE_CHUNK_STORE_DIR})

####    TESTS    ####
file(GLOB SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/tests/*.cc")
file(GLOB HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/tests/*.h")
set(ALL_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})
source_group("Chunk Actions Tests Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})
source_group("Chunk Actions Tests Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})

file(GLOB SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/*.cc")
file(GLOB HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/*.h")
set(ALL_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
source_group("Chunk Store Tests Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
source_group("Chunk Store Tests Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})

###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(private ${ALL_FILES_PRIVATE_DIR} ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${ALL_FILES_PRIVATE_CHUNK_STORE_DIR})
ms_add_executable(TESTprivate "Tests/Private" ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR} ${ALL_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
ms_add_executable(TESTprocess "Tests/Private" "${PROJECT_SOURCE_DIR}/src/maidsafe/private/process/tests/process_test.cc")

target_link_libraries(maidsafe_private maidsafe_common)
target_link_libraries(TESTprivate maidsafe_private)
target_link_libraries(TESTprocess maidsafe_private  boost_program_options-static)
rename_outdated_built_exes()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)

file(GLOB_RECURSE PROTO_SOURCE_FILES "${PROTO_SOURCE_DIR}/maidsafe/*.pb.cc")
file(GLOB_RECURSE PROTO_HEADER_FILES "${PROJECT_SOURCE_DIR}/include/maidsafe/*.pb.h")
ms_disable_warnings(${PROTO_SOURCE_FILES})
if(UNIX)
  SET_SOURCE_FILES_PROPERTIES("${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/mock_chunk_manager.cc"
                              "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/mock_chunk_manager.h"
                               PROPERTIES COMPILE_FLAGS "-Wno-effc++")
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/threadsafe_chunk_store_test.cc
                                PROPERTIES COMPILE_FLAGS "-Wstrict-overflow=2")
endif()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
set(ALL_PRIVATE_STYLE ${ALL_FILES_PRIVATE_DIR} ${ALL_FILES_PRIVATE_TESTS_DIR} ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${ALL_FILES_PRIVATE_CHUNK_STORE_DIR})
list(REMOVE_ITEM ALL_PRIVATE_STYLE ${PROTO_SOURCE_FILES} ${PROTO_HEADER_FILES})
add_style_test(${ALL_PRIVATE_STYLE})
add_gtests(TESTprivate)
add_project_experimental()
test_summary_output()
