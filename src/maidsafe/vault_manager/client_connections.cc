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

#include "maidsafe/vault_manager/client_connections.h"

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"

namespace maidsafe {

namespace vault_manager {

void ClientConnections::Add(TcpConnectionPtr connection) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  if (!clients_.emplace(connection, MaidName{}).second) {
    LOG(kError) << "This client TCP connection has already been added.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
}

void ClientConnections::Validate(TcpConnectionPtr connection, const asymm::PlainText& plain_text,
                                 const asymm::Signature& signature,
                                 const passport::PublicMaid& maid) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(clients_.find(connection));
  if (itr == std::end(clients_)) {
    LOG(kError) << "Client TCP connection not found.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  if (itr->second->IsInitialised()) {
    LOG(kError) << "Client TCP connection already validated.";
    clients_.erase(itr);
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::unable_to_handle_request));
  }
  if (!asymm::CheckSignature(plain_text, signature, maid.public_key())) {
    LOG(kError) << "Client TCP connection validation failed.";
    clients_.erase(itr);
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  itr->second = maid.name();
}

void ClientConnections::Remove(TcpConnectionPtr connection) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  if (!clients_.erase(connection))
    LOG(kWarning) << "Client TCP connection not found.";
}

ClientConnections::MaidName ClientConnections::FindValidated(TcpConnectionPtr connection) const {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(clients_.find(connection));
  if (itr == std::end(clients_)) {
    LOG(kError) << "Client TCP connection not found.";
    BOOST_THROW_EXCEPTION(MakeError(CommonErrors::invalid_parameter));
  }
  if (!itr->second->IsInitialised())
    LOG(kInfo) << "Client TCP connection found, but not yet validated.";
  return itr->second;
}

}  //  namespace vault_manager

}  //  namespace maidsafe
