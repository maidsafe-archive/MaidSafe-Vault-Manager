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

#include "maidsafe/common/utils.h"
#include "maidsafe/passport/passport.h"

#include "maidsafe/vault_manager/interprocess_messages.pb.h"
#include "maidsafe/vault_manager/tcp_connection.h"
#include "maidsafe/vault_manager/utils.h"
#include "maidsafe/vault_manager/vault_info.h"

namespace maidsafe {

namespace vault_manager {

namespace {

void SetVaultKeys(const passport::PmidAndSigner& pmid_and_signer,
                  protobuf::VaultKeys* proto_vault_keys) {
  crypto::AES256Key symm_key{ RandomString(crypto::AES256_KeySize) };
  crypto::AES256InitialisationVector symm_iv{ RandomString(crypto::AES256_IVSize) };
  proto_vault_keys->set_aes256key(symm_key.string());
  proto_vault_keys->set_aes256iv(symm_iv.string());
  proto_vault_keys->set_encrypted_anpmid(
      passport::EncryptAnpmid(pmid_and_signer.second, symm_key, symm_iv)->string());
  proto_vault_keys->set_encrypted_pmid(
      passport::EncryptPmid(pmid_and_signer.first, symm_key, symm_iv)->string());
}

}  // unnamed namespace

void SendChallenge(TcpConnectionPtr connection, const asymm::PlainText& challenge) {
  protobuf::Challenge message;
  message.set_plaintext(challenge.string());
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kChallenge)));
}

void SendChallengeResponse(TcpConnectionPtr connection, const passport::PublicMaid& public_maid,
                           const asymm::Signature& signature) {
  protobuf::ChallengeResponse message;
  message.set_public_maid_name(public_maid.name()->string());
  message.set_public_maid_value(public_maid.Serialise()->string());
  message.set_signature(signature.string());
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kChallengeResponse)));
}

void SendStartVaultRequest(TcpConnectionPtr connection,
                           const boost::filesystem::path& chunkstore_path,
                           DiskUsage max_disk_usage) {
  protobuf::StartVaultRequest message;
  message.set_chunkstore_path(chunkstore_path.string());
  message.set_max_disk_usage(max_disk_usage.data);
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kStartVaultRequest)));
}

void SendStartVaultResponse(TcpConnectionPtr connection,
                            const passport::PmidAndSigner& pmid_and_signer,
                            const maidsafe_error* const error) {
  protobuf::StartVaultResponse message;
  if (error)
    message.set_serialised_maidsafe_error(Serialise(*error).data);
  else
    SetVaultKeys(pmid_and_signer, message.mutable_vault_keys());
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kStartVaultResponse)));
}

void SendTakeOwnershipRequest(TcpConnectionPtr connection, const std::string& vault_label,
                              const boost::filesystem::path& chunkstore_path,
                              DiskUsage max_disk_usage) {
  protobuf::TakeOwnershipRequest message;
  message.set_label(vault_label);
  message.set_chunkstore_path(chunkstore_path.string());
  message.set_max_disk_usage(max_disk_usage.data);
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kTakeOwnershipRequest)));
}

void SendTakeOwnershipResponse(TcpConnectionPtr connection,
                               const passport::PmidAndSigner& pmid_and_signer,
                               const maidsafe_error* const error) {
  protobuf::TakeOwnershipResponse message;
  if (error)
    message.set_serialised_maidsafe_error(Serialise(*error).data);
  else
    SetVaultKeys(pmid_and_signer, message.mutable_vault_keys());
  connection->Send(WrapMessage(std::make_pair(message.SerializeAsString(),
                   MessageType::kTakeOwnershipResponse)));
}

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
