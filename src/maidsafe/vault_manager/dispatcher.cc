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

#include "maidsafe/vault_manager/dispatcher.h"

#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/interprocess_messages.pb.h"
#include "maidsafe/vault_manager/tcp_connection.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

void SendVaultStartedResponse(VaultInfo& vault_info, crypto::AES256Key symm_key,
                              crypto::AES256InitialisationVector symm_iv,
                              const routing::BootstrapContacts& bootstrap_contacts) {
  protobuf::VaultStartedResponse message;
  message.set_pmid(passport::EncryptPmid(*vault_info.pmid, symm_key, symm_iv)->string());
  message.set_chunkstore_path(vault_info.chunkstore_path.string());
  message.set_max_disk_usage(vault_info.max_disk_usage.data);
  message.set_serialised_bootstrap_contacts(
      routing::SerialiseBootstrapContacts(bootstrap_contacts));
  vault_info.tcp_connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                                                             MessageType::kVaultStartedResponse)));
}

void SendVaultShutdownRequest(TcpConnectionPtr connection) {
  connection->Send(WrapMessage(std::make_pair(std::string{}, MessageType::kVaultShutdownRequest)));
}

void SendMaxDiskUsageUpdate(TcpConnectionPtr connection, DiskUsage max_disk_usage) {
  protobuf::MaxDiskUsageUpdate message;
  message.set_max_disk_usage(max_disk_usage.data);
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                                              MessageType::kMaxDiskUsageUpdate)));
}

}  //  namespace vault_manager

}  //  namespace maidsafe
