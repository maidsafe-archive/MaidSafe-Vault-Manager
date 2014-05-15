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

#ifndef MAIDSAFE_VAULT_MANAGER_CLIENT_CONNECTIONS_H_
#define MAIDSAFE_VAULT_MANAGER_CLIENT_CONNECTIONS_H_

#include <map>
#include <memory>
#include <mutex>
#include <utility>

#include "boost/asio/io_service.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

class TcpConnection;
typedef std::shared_ptr<TcpConnection> TcpConnectionPtr;

class ClientConnections {
 public:
  typedef passport::PublicMaid::Name MaidName;
  explicit ClientConnections(boost::asio::io_service& io_service);
  void Add(TcpConnectionPtr connection, const asymm::PlainText& challenge);
  void Validate(TcpConnectionPtr connection, const passport::PublicMaid& maid,
                const asymm::Signature& signature);
  bool Remove(TcpConnectionPtr connection);
  MaidName FindValidated(TcpConnectionPtr connection) const;
  TcpConnectionPtr FindValidated(MaidName maid_name) const;

 private:
  boost::asio::io_service& io_service_;
  mutable std::mutex mutex_;
  std::map<TcpConnectionPtr, std::pair<asymm::PlainText, TimerPtr>,
           std::owner_less<TcpConnectionPtr>> unvalidated_clients_;
  std::map<TcpConnectionPtr, MaidName, std::owner_less<TcpConnectionPtr>> clients_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_CLIENT_CONNECTIONS_H_
