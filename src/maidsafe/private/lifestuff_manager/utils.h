/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_UTILS_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_UTILS_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boost/filesystem/path.hpp"

#include "maidsafe/private/lifestuff_manager/local_tcp_transport.h"


namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

enum class MessageType;

namespace detail {

std::string WrapMessage(const MessageType& message_type, const std::string& payload);

bool UnwrapMessage(const std::string& wrapped_message,
                   MessageType& message_type,
                   std::string& payload);

// Returns a string which can be used as the --vmid argument of the PD vault.
std::string GenerateVmidParameter(const uint32_t& process_index,
                                  const uint16_t& lifestuff_manager_port);

// Parses a --vmid argument of the PD vault into its constituent parts.
bool ParseVmidParameter(const std::string& lifestuff_manager_identifier,
                        uint32_t& process_index,
                        uint16_t& lifestuff_manager_port);

bool StartControllerListeningPort(std::shared_ptr<LocalTcpTransport> transport,
                                  OnMessageReceived::slot_type on_message_received_slot,
                                  Port& local_port);

#ifdef TESTING
void SetTestEnvironmentVariables(Port test_lifestuff_manager_port,
                                 boost::filesystem::path test_env_root_dir,
                                 boost::filesystem::path path_to_vault,
                                 std::vector<std::string> bootstrap_ips);
Port GetTestLifeStuffManagerPort();
boost::filesystem::path GetTestEnvironmentRootDir();
boost::filesystem::path GetPathToVault();
std::vector<std::string> GetBootstrapIps();
bool UsingDefaultEnvironment();
#endif

}  // namespace detail

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_UTILS_H_
