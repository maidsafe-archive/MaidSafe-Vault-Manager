#==============================================================================#
#                                                                              #
#  Copyright (c) 2011 MaidSafe.net limited                                     #
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
if(RAN_PROTOC)
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
FILE(GLOB SOURCE_FILES_PRIVATE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/*.cc")
FILE(GLOB HEADER_FILES_PRIVATE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/*.h")
SET(ALL_FILES_PRIVATE_DIR ${SOURCE_FILES_PRIVATE_DIR} ${HEADER_FILES_PRIVATE_DIR})
SOURCE_GROUP("Private Source Files" FILES ${SOURCE_FILES_PRIVATE_DIR})
SOURCE_GROUP("Private Header Files" FILES ${HEADER_FILES_PRIVATE_DIR})

FILE(GLOB SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/*.cc")
FILE(GLOB HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/*.h")
SET(ALL_FILES_PRIVATE_CHUNK_ACTIONS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
SOURCE_GROUP("Chunk Actions Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_DIR})
SOURCE_GROUP("Chunk Actions Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_DIR})

FILE(GLOB SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/*.cc")
FILE(GLOB HEADER_FILES_PRIVATE_CHUNK_STORE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/*.h")
SET(ALL_FILES_PRIVATE_CHUNK_STORE_DIR ${SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR} ${HEADER_FILES_PRIVATE_CHUNK_STORE_DIR})
SOURCE_GROUP("Chunk Store Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_STORE_DIR})
SOURCE_GROUP("Chunk Store Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_STORE_DIR})

####    TESTS    ####
FILE(GLOB SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/tests/*.cc")
FILE(GLOB HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_actions/tests/*.h")
SET(ALL_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})
SOURCE_GROUP("Chunk Actions Tests Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})
SOURCE_GROUP("Chunk Actions Tests Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR})

FILE(GLOB SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/*.cc")
FILE(GLOB HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_store/tests/*.h")
SET(ALL_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR ${SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR} ${HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
SOURCE_GROUP("Chunk Store Tests Source Files" FILES ${SOURCE_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})
SOURCE_GROUP("Chunk Store Tests Header Files" FILES ${HEADER_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(private ${ALL_FILES_PRIVATE_DIR} ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${ALL_FILES_PRIVATE_CHUNK_STORE_DIR})
ms_add_executable(TESTprivate Tests ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_TESTS_DIR} ${ALL_FILES_PRIVATE_CHUNK_STORE_TESTS_DIR})

TARGET_LINK_LIBRARIES(maidsafe_private maidsafe_common)
TARGET_LINK_LIBRARIES(TESTprivate maidsafe_private)

rename_outdated_built_exes()

###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

FILE(GLOB_RECURSE PROTO_SOURCE_FILES "${PROTO_SOURCE_DIR}/maidsafe/*.pb.cc")
FILE(GLOB_RECURSE PROTO_HEADER_FILES "${PROJECT_SOURCE_DIR}/include/maidsafe/*.pb.h")
ms_disable_warnings(${PROTO_SOURCE_FILES})


###################################################################################################
# Tests                                                                                           #
###################################################################################################
SET(ALL_PRIVATE_STYLE ${ALL_FILES_PRIVATE_DIR} ${ALL_FILES_PRIVATE_TESTS_DIR} ${ALL_FILES_PRIVATE_CHUNK_ACTIONS_DIR} ${ALL_FILES_PRIVATE_CHUNK_STORE_DIR})
LIST(REMOVE_ITEM ALL_PRIVATE_STYLE ${PROTO_SOURCE_FILES} ${PROTO_HEADER_FILES})
add_style_test(${ALL_PRIVATE_STYLE})
add_gtests(TESTprivate)
test_summary_output()
