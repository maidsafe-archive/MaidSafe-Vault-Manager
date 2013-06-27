/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
