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

#include "maidsafe/common/crypto.h"
#include "maidsafe/routing/bootstrap_file_operations.h"

namespace maidsafe {

namespace vault_manager {

class TcpConnection;
typedef std::shared_ptr<TcpConnection> TcpConnectionPtr;
struct VaultInfo;

void SendVaultStartedResponse(VaultInfo& vault_info, crypto::AES256Key symm_key,
                              crypto::AES256InitialisationVector symm_iv,
                              const routing::BootstrapContacts& bootstrap_contacts);

void SendVaultShutdownRequest(TcpConnectionPtr connection);

void SendMaxDiskUsageUpdate(TcpConnectionPtr connection, DiskUsage max_disk_usage);

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_DISPATCHER_H_