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

#include "maidsafe/vault_manager/new_connections.h"

#include <future>

#include "maidsafe/common/error.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/tcp/connection.h"

namespace maidsafe {

namespace vault_manager {

NewConnections::NewConnections(asio::io_service& io_service)
    : io_service_(io_service), connections_() {}

std::shared_ptr<NewConnections> NewConnections::MakeShared(asio::io_service& io_service) {
  return std::shared_ptr<NewConnections>{ new NewConnections{ io_service } };
}

NewConnections::~NewConnections() {
  assert(connections_.empty());
}

void NewConnections::Add(tcp::ConnectionPtr connection) {
  TimerPtr timer{ std::make_shared<Timer>(io_service_, kRpcTimeout) };
  timer->async_wait([connection](const std::error_code& error_code) {
    if (error_code && error_code == asio::error::operation_aborted) {
      LOG(kVerbose) << "New connection timer cancelled OK.";
    } else {
      LOG(kWarning) << "Timed out waiting for new connection to identify itself.";
      connection->Close();
    }
  });
  bool result{ connections_.emplace(connection, timer).second };
  assert(result);
  static_cast<void>(result);
}

bool NewConnections::Remove(tcp::ConnectionPtr connection) {
  return connections_.erase(connection) == 1U;
}

void NewConnections::CloseAll() {
  for (auto connection : connections_)
    connection.first->Close();
}

}  //  namespace vault_manager

}  //  namespace maidsafe
