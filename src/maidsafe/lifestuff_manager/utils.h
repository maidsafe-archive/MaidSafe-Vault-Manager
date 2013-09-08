/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_UTILS_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_UTILS_H_

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "boost/asio/ip/udp.hpp"
#include "boost/filesystem/path.hpp"

#include "maidsafe/lifestuff_manager/local_tcp_transport.h"


namespace maidsafe {

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
void ParseVmidParameter(const std::string& lifestuff_manager_identifier,
                        uint32_t& process_index,
                        uint16_t& lifestuff_manager_port);

void StartControllerListeningPort(std::shared_ptr<LocalTcpTransport> transport,
                                  OnMessageReceived::slot_type on_message_received_slot,
                                  Port& local_port);

#ifdef TESTING
void SetTestEnvironmentVariables(Port test_lifestuff_manager_port,
                                 boost::filesystem::path test_env_root_dir,
                                 boost::filesystem::path path_to_vault,
                                 std::vector<boost::asio::ip::udp::endpoint> bootstrap_ips);
Port GetTestLifeStuffManagerPort();
boost::filesystem::path GetTestEnvironmentRootDir();
boost::filesystem::path GetPathToVault();
std::vector<boost::asio::ip::udp::endpoint> GetBootstrapIps();
void SetIdentityIndex(int identity_index);
int IdentityIndex();
bool UsingDefaultEnvironment();
#endif

}  // namespace detail

}  // namespace lifestuff_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_UTILS_H_
