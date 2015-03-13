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
#include "maidsafe/common/on_scope_exit.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/tcp/connection.h"

namespace maidsafe {

namespace vault_manager {

ClientConnections::ClientConnections(asio::io_service& io_service)
    : io_service_(io_service), unvalidated_clients_(), clients_() {}

std::shared_ptr<ClientConnections> ClientConnections::MakeShared(asio::io_service& io_service) {
  return std::shared_ptr<ClientConnections>{new ClientConnections{io_service}};
}

ClientConnections::~ClientConnections() {
  assert(unvalidated_clients_.empty() && clients_.empty());
}

void ClientConnections::Add(tcp::ConnectionPtr connection, const asymm::PlainText& challenge) {
  assert(clients_.find(connection) == std::end(clients_));
  TimerPtr timer{std::make_shared<Timer>(io_service_, kRpcTimeout)};
  timer->async_wait([=](const std::error_code& error_code) {
    if (!error_code || error_code != asio::error::operation_aborted) {
      LOG(kWarning) << "Timed out waiting for Client to validate.";
      connection->Close();
    }
  });
  bool result{unvalidated_clients_.emplace(connection, std::make_pair(challenge, timer)).second};
  assert(result);
  static_cast<void>(result);
}

void ClientConnections::Validate(tcp::ConnectionPtr connection, const passport::PublicMaid& maid,
                                 const asymm::Signature& signature) {
  auto itr(unvalidated_clients_.find(connection));
  if (itr == std::end(unvalidated_clients_)) {
    LOG(kError) << "Unvalidated Client TCP connection not found.";
    BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::connection_not_found));
  }

  on_scope_exit cleanup{[this, itr] { itr->first->Close(); }};

  if (asymm::CheckSignature(itr->second.first, signature, maid.public_key())) {
    LOG(kSuccess) << "Client " << maid.Name() << " TCP connection validated.";
  } else {
    LOG(kError) << "Client TCP connection validation failed.";
    BOOST_THROW_EXCEPTION(MakeError(AsymmErrors::invalid_signature));
  }

  bool result{clients_.emplace(connection, maid.Name()).second};
  unvalidated_clients_.erase(itr);
  cleanup.Release();
  assert(result);
  static_cast<void>(result);
}

bool ClientConnections::Remove(tcp::ConnectionPtr connection) {
  auto itr(clients_.find(connection));
  if (itr != std::end(clients_)) {
    clients_.erase(itr);
    return true;
  }

  auto unvalidated_itr(unvalidated_clients_.find(connection));
  if (unvalidated_itr != std::end(unvalidated_clients_)) {
    unvalidated_clients_.erase(unvalidated_itr);
    return true;
  }

  return false;
}

void ClientConnections::CloseAll() {
  for (auto connection : unvalidated_clients_)
    connection.first->Close();
  for (auto connection : clients_)
    connection.first->Close();
}

ClientConnections::MaidName ClientConnections::FindValidated(tcp::ConnectionPtr connection) const {
  auto itr(clients_.find(connection));
  if (itr == std::end(clients_)) {
    auto unvalidated_itr(unvalidated_clients_.find(connection));
    if (unvalidated_itr == std::end(unvalidated_clients_)) {
      LOG(kError) << "Client TCP connection not found.";
      BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::connection_not_found));
    } else {
      LOG(kWarning) << "Client TCP connection found, but not yet validated.";
      BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::unvalidated_client));
    }
  }
  return itr->second;
}

tcp::ConnectionPtr ClientConnections::FindValidated(MaidName maid_name) const {
  auto itr(std::find_if(std::begin(clients_), std::end(clients_),
                        [&maid_name](const std::pair<tcp::ConnectionPtr, MaidName> client) {
    return client.second == maid_name;
  }));
  if (itr == std::end(clients_)) {
    LOG(kWarning) << "Client TCP connection not found.";
    BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::connection_not_found));
  }
  return itr->first;
}

std::vector<tcp::ConnectionPtr> ClientConnections::GetAll() const {
  std::vector<tcp::ConnectionPtr> all_connections;
  for (auto connection : clients_)
    all_connections.push_back(connection.first);
  for (auto connection : unvalidated_clients_)
    all_connections.push_back(connection.first);
  return all_connections;
}

}  //  namespace vault_manager

}  //  namespace maidsafe
