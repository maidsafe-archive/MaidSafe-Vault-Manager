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

#include "maidsafe/common/process.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/tcp/connection.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/interprocess_messages.pb.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace vault_manager {

namespace {

void DoSendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                             const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
                             const std::string& vlog_session_id,
                             const bool* const send_hostname_to_visualiser_server,
                             const int* const pmid_list_index) {
  protobuf::StartVaultRequest message;
  message.set_label(vault_label.string());
  if (!vault_dir.empty())
    message.set_vault_dir(vault_dir.string());
  message.set_max_disk_usage(max_disk_usage.data);
  message.set_vlog_session_id(vlog_session_id);
  if (send_hostname_to_visualiser_server)
    message.set_send_hostname_to_visualiser_server(*send_hostname_to_visualiser_server);
  if (pmid_list_index)
    message.set_pmid_list_index(*pmid_list_index);
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                                              MessageType::kStartVaultRequest)));
}

}  // unnamed namespace

void SendValidateConnectionRequest(tcp::ConnectionPtr connection) {
  connection->Send(WrapMessage(std::make_pair(std::string{},
                                              MessageType::kValidateConnectionRequest)));
}

void SendChallenge(tcp::ConnectionPtr connection, const asymm::PlainText& challenge) {
  protobuf::Challenge message;
  message.set_plaintext(challenge.string());
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kChallenge)));
}

void SendChallengeResponse(tcp::ConnectionPtr connection, const passport::PublicMaid& public_maid,
                           const asymm::Signature& signature) {
  protobuf::ChallengeResponse message;
  message.set_public_maid_name(public_maid.name()->string());
  message.set_public_maid_value(public_maid.Serialise()->string());
  message.set_signature(signature.string());
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kChallengeResponse)));
}

void SendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                           const fs::path& vault_dir, DiskUsage max_disk_usage,
                           const std::string& vlog_session_id) {
  DoSendStartVaultRequest(connection, vault_label, vault_dir, max_disk_usage, vlog_session_id,
                          nullptr, nullptr);
}

void SendTakeOwnershipRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                              const fs::path& vault_dir, DiskUsage max_disk_usage) {
  protobuf::TakeOwnershipRequest message;
  message.set_label(vault_label.string());
  message.set_vault_dir(vault_dir.string());
  message.set_max_disk_usage(max_disk_usage.data);
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kTakeOwnershipRequest)));
}

void SendVaultRunningResponse(tcp::ConnectionPtr connection,
                              const NonEmptyString& vault_label,
                              const passport::PmidAndSigner* const pmid_and_signer,
                              const maidsafe_error* const error) {
  protobuf::VaultRunningResponse message;
  if (error) {
    assert(!pmid_and_signer);
    message.set_label(vault_label.string());
    message.set_serialised_maidsafe_error(Serialise(*error).data);
  } else {
    assert(pmid_and_signer);
    message.set_label(vault_label.string());
    crypto::AES256Key symm_key{ RandomString(crypto::AES256_KeySize) };
    crypto::AES256InitialisationVector symm_iv{ RandomString(crypto::AES256_IVSize) };
    message.mutable_vault_keys()->set_aes256key(symm_key.string());
    message.mutable_vault_keys()->set_aes256iv(symm_iv.string());
    message.mutable_vault_keys()->set_encrypted_anpmid(
        passport::EncryptAnpmid(pmid_and_signer->second, symm_key, symm_iv)->string());
    message.mutable_vault_keys()->set_encrypted_pmid(
        passport::EncryptPmid(pmid_and_signer->first, symm_key, symm_iv)->string());
  }
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kVaultRunningResponse)));
}

void SendVaultStarted(tcp::ConnectionPtr connection) {
  protobuf::VaultStarted message;
  message.set_process_id(process::GetProcessId());
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                                              MessageType::kVaultStarted)));
}

void SendVaultStartedResponse(VaultInfo& vault_info, crypto::AES256Key symm_key,
                              crypto::AES256InitialisationVector symm_iv,
                              const routing::BootstrapContacts& bootstrap_contacts) {
  protobuf::VaultStartedResponse message;
  message.set_aes256key(symm_key.string());
  message.set_aes256iv(symm_iv.string());
  message.set_encrypted_pmid(
      passport::EncryptPmid(vault_info.pmid_and_signer->first, symm_key, symm_iv)->string());
  message.set_vault_dir(vault_info.vault_dir.string());
  message.set_max_disk_usage(vault_info.max_disk_usage.data);
  message.set_serialised_bootstrap_contacts(
      routing::SerialiseBootstrapContacts(bootstrap_contacts));
#ifdef TESTING
  auto serialised_public_pmids = GetSerialisedPublicPmids();
  if (!serialised_public_pmids.empty())
    message.set_serialised_public_pmids(serialised_public_pmids);
#endif
  vault_info.tcp_connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                                                             MessageType::kVaultStartedResponse)));
}

void SendBootstrapContact(tcp::ConnectionPtr connection,
                          const routing::BootstrapContact& bootstrap_contact) {
  protobuf::BootstrapContact message;
//  assert(false);  static_cast<void>(bootstrap_contact);
  message.set_serialised_contact(routing::SerialiseBootstrapContact(bootstrap_contact));
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                               MessageType::kBootstrapContact)));
}

void SendJoinedNetwork(tcp::ConnectionPtr connection) {
  connection->Send(WrapMessage(std::make_pair(std::string{}, MessageType::kJoinedNetwork)));
}

void SendBootstrapContactsRequest(tcp::ConnectionPtr connection) {
  connection->Send(WrapMessage(std::make_pair(std::string{},
                                              MessageType::kBootstrapContactsRequest)));
}

void SendBootstrapContactsResponse(tcp::ConnectionPtr connection,
                                   const routing::BootstrapContacts& bootstrap_contacts) {
  protobuf::BootstrapContactsResponse message;
  message.set_serialised_bootstrap_contacts(
      routing::SerialiseBootstrapContacts(bootstrap_contacts));
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                               MessageType::kBootstrapContactsResponse)));
}

void SendVaultShutdownRequest(tcp::ConnectionPtr connection) {
  connection->Send(WrapMessage(std::make_pair(std::string{}, MessageType::kVaultShutdownRequest)));
}

void SendMaxDiskUsageUpdate(tcp::ConnectionPtr connection, DiskUsage max_disk_usage) {
  protobuf::MaxDiskUsageUpdate message;
  message.set_max_disk_usage(max_disk_usage.data);
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                                              MessageType::kMaxDiskUsageUpdate)));
}

void SendLogMessage(tcp::ConnectionPtr connection, const std::string& log_message) {
  connection->Send(WrapMessage(std::make_pair(log_message, MessageType::kLogMessage)));
}

#ifdef TESTING
void SendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                           const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
                           const std::string& vlog_session_id,
                           bool send_hostname_to_visualiser_server) {
  DoSendStartVaultRequest(connection, vault_label, vault_dir, max_disk_usage, vlog_session_id,
                          &send_hostname_to_visualiser_server, nullptr);
}

void SendStartVaultRequest(tcp::ConnectionPtr connection, const NonEmptyString& vault_label,
                           const boost::filesystem::path& vault_dir, DiskUsage max_disk_usage,
                           const std::string& vlog_session_id,
                           bool send_hostname_to_visualiser_server, int pmid_list_index) {
  DoSendStartVaultRequest(connection, vault_label, vault_dir, max_disk_usage, vlog_session_id,
                          &send_hostname_to_visualiser_server, &pmid_list_index);
}

void SendMarkNetworkAsStableRequest(tcp::ConnectionPtr connection) {
  connection->Send(WrapMessage(std::make_pair(std::string{}, MessageType::kMarkNetworkAsStable)));
}

void SendNetworkStableRequest(tcp::ConnectionPtr connection) {
  connection->Send(WrapMessage(std::make_pair(std::string{}, MessageType::kNetworkStableRequest)));
}

void SendNetworkStableResponse(tcp::ConnectionPtr connection) {
  connection->Send(WrapMessage(std::make_pair(std::string{}, MessageType::kNetworkStableResponse)));
}
#endif

}  //  namespace vault_manager

}  //  namespace maidsafe
