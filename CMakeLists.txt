# ============================================================================ #
#                                                                              #
# Copyright [2011] maidsafe.net limited                                        #
#                                                                              #
# The following source code is property of maidsafe.net limited and is not     #
# meant for external use.  The use of this code is governed by the license     #
# file licence.txt found in the root of this directory and also on             #
# www.maidsafe.net.                                                            #
#                                                                              #
# You are not free to copy, amend or otherwise use this source code without    #
# the explicit written permission of the board of directors of maidsafe.net.   #
#                                                                              #
# ============================================================================ #


CMAKE_MINIMUM_REQUIRED(VERSION 2.8.4 FATAL_ERROR)
MESSAGE("================================================================================\n")

SET(ERROR_MESSAGE_CMAKE_PATH "cmake ../../..")
GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after PROJECT command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..\\..")
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()

SET(ERROR_MESSAGE "No generator previously specified.\nTo see a full list of generators, run:\n\t${ERROR_MESSAGE_CMAKE_PATH} --help\n")
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  SET(PROJECT_NAME maidsafe_private)
ELSE()
  SET(PROJECT_NAME maidsafe_private_${CMAKE_BUILD_TYPE_DIR})
ENDIF()
OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)


# This call resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
PROJECT(${PROJECT_NAME})
SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)

###################################################################################################
# MaidSafe Common and DHT library search                                                          #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)

###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
INCLUDE(maidsafe_standard_setup)
HANDLE_VERSIONS(${PROJECT_SOURCE_DIR}/src/maidsafe/private/version.h)

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
FILE(GLOB SOURCE_FILES_PRIVATE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/*.cc")
FILE(GLOB HEADER_FILES_PRIVATE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/*.h")
SET(ALL_FILES_PRIVATE_DIR ${SOURCE_FILES_PRIVATE_DIR} ${HEADER_FILES_PRIVATE_DIR})
SOURCE_GROUP("private Source Files" FILES ${SOURCE_FILES_PRIVATE_DIR})
SOURCE_GROUP("private Header Files" FILES ${HEADER_FILES_PRIVATE_DIR})

FILE(GLOB ALL_FILES_PRIVATE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/private/tests/*.cc" "${PROJECT_SOURCE_DIR}/src/maidsafe/private/tests/*.h")

###################################################################################################
# All Platforms:  Add Test Exes and Create all maidsafe_private libs                              #
###################################################################################################
ADD_LIBRARY(maidsafe_private_static STATIC ${ALL_FILES_PRIVATE_DIR})
ADD_EXECUTABLE(TESTmaidsafe_private ${ALL_FILES_PRIVATE_TESTS_DIR})
# Force renaming of exes to match standard CMake library renaming policy
RENAME_EXECUTABLE(TESTmaidsafe_private)

SET_TARGET_PROPERTIES(maidsafe_private_static PROPERTIES OUTPUT_NAME maidsafe_private)

TARGET_LINK_LIBRARIES(maidsafe_private_static maidsafe_common_static boost_serialization)
TARGET_LINK_LIBRARIES(TESTmaidsafe_private maidsafe_private_static gtest_static)

###################################################################################################
# Builds                                                                                          #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

IF(MSVC)
  # C4503 'decorated name length exceeded' caused by boost multi-index and signals2
  # Disabled as per advice at https://svn.boost.org/trac/boost/wiki/Guidelines/WarningsGuidelines
  # C4512 'assignment operator could not be generated' caused by boost signals2
  # Disabled as per advice at http://lists.boost.org/boost-users/2009/01/44368.php
  # C4996 'Function call with parameters that may be unsafe' caused by boost signals2
  # Disabled as per advice at https://svn.boost.org/trac/boost/wiki/Guidelines/WarningsGuidelines
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /wd4503 /wd4512 /wd4996")
  SET_TARGET_PROPERTIES(maidsafe_private_static PROPERTIES STATIC_LIBRARY_FLAGS_RELEASE "/LTCG")
  SET_TARGET_PROPERTIES(TESTmaidsafe_private PROPERTIES
                          LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
                          LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
                          LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
                          LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
ENDIF()

###################################################################################################
# Tests                                                                                           #
###################################################################################################
IF(PYTHONINTERP_FOUND)
  IF(UNIX)
    ADD_TEST(STYLE_CHECK python ${MaidSafeCommon_TOOLS_DIR}/cpplint.py ${ALL_FILES_PRIVATE_DIR} ${ALL_FILES_PRIVATE_TESTS_DIR})
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${PROJECT_SOURCE_DIR})
    ADD_TEST(STYLE_CHECK ${MaidSafeCommon_TOOLS_DIR}/run_cpplint.bat ${STYLE_CHECK_SOURCE} ${MaidSafeCommon_TOOLS_DIR}/cpplint.py)
  ENDIF()
  SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
ENDIF()

ADD_GTESTS(TESTmaidsafe_private)

TEST_SUMMARY_OUTPUT()

###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()

SET(MAIDSAFE_PRIVATE_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe/private/chunk_action_authority.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/private/version.h)
FOREACH(MAIDSAFE_PRIVATE_INSTALL_FILE ${MAIDSAFE_PRIVATE_INSTALL_FILES})
  CHECK_INSTALL_HEADER_HAS_VERSION_GUARD(${MAIDSAFE_PRIVATE_INSTALL_FILE})
ENDFOREACH()

SET(EXPORT_NAME maidsafe_private)
INSTALL(TARGETS maidsafe_private_static EXPORT ${EXPORT_NAME} ARCHIVE DESTINATION lib)
INSTALL(FILES ${MAIDSAFE_PRIVATE_INSTALL_FILES} DESTINATION include/maidsafe/private)
INSTALL(EXPORT ${EXPORT_NAME} DESTINATION share/maidsafe)
ADD_VERSION_INFO_TO_INSTALLED_FILE()
