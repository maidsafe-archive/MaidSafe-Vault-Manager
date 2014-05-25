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

#include "maidsafe/vault_manager/tcp_connection.h"

namespace maidsafe {

namespace vault_manager {

ClientConnections::ClientConnections(boost::asio::io_service& io_service)
    : io_service_(io_service), mutex_(), unvalidated_clients_(), clients_() {}

void ClientConnections::Add(TcpConnectionPtr connection, const asymm::PlainText& challenge) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  assert(clients_.find(connection) == std::end(clients_));
  TimerPtr timer{ std::make_shared<Timer>(io_service_, kRpcTimeout) };
  timer->async_wait([=](const boost::system::error_code& error_code) {
    if (error_code && error_code == boost::asio::error::operation_aborted) {
      LOG(kVerbose) << "Client connection timer cancelled OK.";
    } else {
      LOG(kWarning) << "Timed out waiting for Client to validate.";
      connection->Close();
      std::lock_guard<std::mutex> lock{ mutex_ };
      unvalidated_clients_.erase(connection);
    }
  });
  bool result{ unvalidated_clients_.emplace(connection, std::make_pair(challenge, timer)).second };
  assert(result);
  static_cast<void>(result);
}

void ClientConnections::Validate(TcpConnectionPtr connection, const passport::PublicMaid& maid,
                                 const asymm::Signature& signature) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(unvalidated_clients_.find(connection));
  if (itr == std::end(unvalidated_clients_)) {
    LOG(kError) << "Unvalidated Client TCP connection not found.";
    BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::connection_not_found));
  }

  on_scope_exit cleanup{ [this, itr] {
    itr->first->Close();
    unvalidated_clients_.erase(itr);
  } };

  if (asymm::CheckSignature(itr->second.first, signature, maid.public_key())) {
    LOG(kSuccess) << "Client " << DebugId(maid.name().value) << " TCP connection validated.";
  } else {
    LOG(kError) << "Client TCP connection validation failed.";
    BOOST_THROW_EXCEPTION(MakeError(AsymmErrors::invalid_signature));
  }

  bool result{ clients_.emplace(connection, maid.name()).second };
  assert(result);
  static_cast<void>(result);
}

bool ClientConnections::Remove(TcpConnectionPtr connection) {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(clients_.find(connection));
  if (itr != std::end(clients_)) {
    itr->first->Close();
    clients_.erase(itr);
    return true;
  }

  auto unvalidated_itr(unvalidated_clients_.find(connection));
  if (unvalidated_itr != std::end(unvalidated_clients_)) {
    unvalidated_itr->first->Close();
    unvalidated_clients_.erase(unvalidated_itr);
    return true;
  }

  return false;
}

ClientConnections::MaidName ClientConnections::FindValidated(TcpConnectionPtr connection) const {
  std::lock_guard<std::mutex> lock{ mutex_ };
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

TcpConnectionPtr ClientConnections::FindValidated(MaidName maid_name) const {
  std::lock_guard<std::mutex> lock{ mutex_ };
  auto itr(std::find_if(std::begin(clients_), std::end(clients_),
                        [&maid_name](const std::pair<TcpConnectionPtr, MaidName> client) {
                          return client.second == maid_name;
                        }));
  if (itr == std::end(clients_)) {
    LOG(kWarning) << "Client TCP connection not found.";
    BOOST_THROW_EXCEPTION(MakeError(VaultManagerErrors::connection_not_found));
  }
  return itr->first;
}

}  //  namespace vault_manager

}  //  namespace maidsafe
