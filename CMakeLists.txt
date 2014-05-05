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

project(vault_manager)

include(../../cmake_modules/standard_setup.cmake)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(VaultManagerSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe/vault_manager)
ms_glob_dir(VaultManager ${VaultManagerSourcesDir} "Vault Manager")
list(REMOVE_ITEM VaultManagerAllFiles "${VaultManagerSourcesDir}/vault_manager_main.cc")

ms_glob_dir(VaultManagerTests ${VaultManagerSourcesDir}/tests "Vault Manager Tests")
list(REMOVE_ITEM VaultManagerTestsAllFiles "${VaultManagerSourcesDir}/tests/dummy_vault.cc")


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(maidsafe_vault_manager ${VaultManagerAllFiles})
target_include_directories(maidsafe_vault_manager PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(maidsafe_vault_manager maidsafe_nfs_client)

ms_add_executable(vault_manager "Production" "${VaultManagerSourcesDir}/vault_manager_main.cc")
target_include_directories(vault_manager PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(vault_manager maidsafe_vault_manager)

ms_rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)
target_compile_definitions(maidsafe_vault_manager PRIVATE COMPANY_NAME=MaidSafe APPLICATION_NAME=VaultManager)


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  ms_add_executable(TESTvault_manager "Tests/Vault Manager" ${VaultManagerTestsAllFiles})
  target_include_directories(TESTvault_manager PRIVATE ${PROJECT_SOURCE_DIR}/src)
  ms_add_executable(dummy_vault "Tests/Vault Manager" "${VaultManagerSourcesDir}/tests/dummy_vault.cc")

  target_link_libraries(TESTvault_manager maidsafe_vault_manager)
  target_link_libraries(dummy_vault maidsafe_vault_manager)

  add_dependencies(TESTvault_manager dummy_vault)

  ms_add_style_test()
  ms_add_gtests(TESTvault_manager)
  ms_add_project_experimental()
  ms_test_summary_output()
endif()
