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
ms_glob_dir(VaultManagerMessages ${VaultManagerSourcesDir}/messages "Vault Manager Messages")

ms_glob_dir(VaultManagerTools ${VaultManagerSourcesDir}/tools "Tools")
set(NetworkTestHelperFile ${VaultManagerSourcesDir}/tools/network_test_helper.cc)
list(REMOVE_ITEM VaultManagerToolsAllFiles ${NetworkTestHelperFile})
ms_glob_dir(VaultManagerToolsCommands ${VaultManagerSourcesDir}/tools/commands "Tool Commands")
ms_glob_dir(VaultManagerToolsActions ${VaultManagerSourcesDir}/tools/actions "Tool Actions")

ms_glob_dir(VaultManagerTests ${VaultManagerSourcesDir}/tests "Vault Manager Tests")
list(REMOVE_ITEM VaultManagerTestsAllFiles "${VaultManagerSourcesDir}/tests/dummy_vault.cc")


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(maidsafe_vault_manager ${VaultManagerAllFiles} ${VaultManagerMessagesAllFiles})
target_include_directories(maidsafe_vault_manager PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(maidsafe_vault_manager maidsafe_nfs_client)

ms_add_executable(vault_manager "Production" "${VaultManagerSourcesDir}/vault_manager_main.cc")
target_include_directories(vault_manager PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(vault_manager maidsafe_vault_manager)
add_dependencies(vault_manager vault)

ms_rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)
target_compile_definitions(maidsafe_vault_manager PRIVATE COMPANY_NAME=MaidSafe APPLICATION_NAME=VaultManager)


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(INCLUDE_TESTS)
  ms_add_executable(test_vault_manager "Tests/Vault Manager" ${VaultManagerTestsAllFiles})
  target_include_directories(test_vault_manager PRIVATE ${PROJECT_SOURCE_DIR}/src)
  ms_add_executable(dummy_vault "Tests/Vault Manager" "${VaultManagerSourcesDir}/tests/dummy_vault.cc")

  target_link_libraries(test_vault_manager maidsafe_vault_manager maidsafe_test)
  target_link_libraries(dummy_vault maidsafe_vault_manager)
  add_dependencies(test_vault_manager dummy_vault)

  ms_add_executable(local_network_controller "Tools/Vault Manager"
                    ${VaultManagerToolsAllFiles}
                    ${VaultManagerToolsCommandsAllFiles}
                    ${VaultManagerToolsActionsAllFiles})
  target_include_directories(local_network_controller PRIVATE ${PROJECT_SOURCE_DIR}/src)
  target_link_libraries(local_network_controller maidsafe_vault_manager maidsafe_nfs_vault maidsafe_routing_test_helper maidsafe_test)
  add_dependencies(local_network_controller vault)

  ms_add_executable(network_test_helper "Tools/Vault Manager" ${NetworkTestHelperFile})
  target_link_libraries(network_test_helper maidsafe_vault_manager)
  add_custom_command(TARGET network_test_helper POST_BUILD
                     COMMAND ${CMAKE_COMMAND} -E copy "${VaultManagerSourcesDir}/tools/network_test_helper.script"
                                                      "$<TARGET_FILE_DIR:network_test_helper>/network_test_helper.script")

  ms_add_default_tests()
  ms_add_gtests(test_vault_manager)
  ms_test_summary_output()
endif()


#==================================================================================================#
# Package                                                                                          #
#==================================================================================================#

#if(UNIX)
#install(TARGETS vault_manager COMPONENT Development DESTINATION /opt/maidsafe/)
#install(FILES ${PROJECT_SOURCE_DIR}/installer/linux/scripts/ubuntu/vault_manager COMPONENT Development DESTINATION /etc/init.d/vault_manager)
#add_custom_command(TARGET vault_manager POST_BUILD
#  COMMAND ${CMAKE_COMMAND} -E copy_if_different
#  ${PROJECT_SOURCE_DIR}/installer/linux/scripts/ubuntu/post_install
#  "${PROJECT_BINARY_DIR}/post_install")

#endif(UNIX)

#if(INCLUDE_TESTS AND NOT $ENV{DESTDIR})
#  install(TARGETS maidsafe_vault_manager COMPONENT Development CONFIGURATIONS Debug Release ARCHIVE DESTINATION lib)
#install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ COMPONENT Development DESTINATION include)
#  install(TARGETS local_network_controller network_test_helper COMPONENT Tools CONFIGURATIONS Debug RUNTIME DESTINATION bin/debug)
#  install(TARGETS local_network_controller network_test_helper COMPONENT Tools CONFIGURATIONS Release RUNTIME DESTINATION bin)
#  install(TARGETS test_vault_manager dummy_vault COMPONENT Tests CONFIGURATIONS Debug RUNTIME DESTINATION bin/debug)
#  install(TARGETS test_vault_manager dummy_vault COMPONENT Tests CONFIGURATIONS Release RUNTIME DESTINATION bin)
#endif()
