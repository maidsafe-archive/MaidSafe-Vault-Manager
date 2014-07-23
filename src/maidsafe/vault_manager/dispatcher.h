/*  Copyright 2014 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_VAULT_MANAGER_DISPATCHER_H_
#define MAIDSAFE_VAULT_MANAGER_DISPATCHER_H_

#include <memory>
#include <string>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/process.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/passport.h"
#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

struct VaultInfo;

void SendValidateConnectionRequest(tcp::ConnectionPtr connection);

void SendChallenge(tcp::ConnectionPtr connection, const asymm::PlainText& challenge);

void SendChallengeResponse(tcp::ConnectionPtr connection, const passport::PublicMaid& public_maid,
                           const asymm::Signature& signature);

#ifdef USE_VLOGGING
void SendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                           const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
                           const std::string& vlog_session_id);
#else
void SendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                           const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage);
#endif

void SendTakeOwnershipRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                              const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage);

void SendVaultRunningResponse(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                              const passport::PmidAndSigner* const pmid_and_signer,
                              const maidsafe_error* const error = nullptr);

void SendVaultStarted(tcp::ConnectionPtr connection);

void SendVaultStartedResponse(VaultInfo& vault_info, crypto::AES256Key symm_key,
                              crypto::AES256InitialisationVector symm_iv);

void SendJoinedNetwork(tcp::ConnectionPtr connection);

void SendVaultShutdownRequest(tcp::ConnectionPtr connection);

void SendMaxDiskUsageUpdate(tcp::ConnectionPtr connection, DiskUsage max_disk_usage);

void SendLogMessage(tcp::ConnectionPtr connection, const std::string& log_message);

#ifdef TESTING
# ifdef USE_VLOGGING
void SendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                           const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
                           const std::string& vlog_session_id,
                           bool send_hostname_to_visualiser_server);

void SendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                           const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
                           const std::string& vlog_session_id,
                           bool send_hostname_to_visualiser_server, int pmid_list_index);
# else
void SendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                           const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
                           int pmid_list_index);
# endif
void SendMarkNetworkAsStableRequest(tcp::ConnectionPtr connection);

void SendNetworkStableRequest(tcp::ConnectionPtr connection);

void SendNetworkStableResponse(tcp::ConnectionPtr connection);
#endif

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_DISPATCHER_H_
