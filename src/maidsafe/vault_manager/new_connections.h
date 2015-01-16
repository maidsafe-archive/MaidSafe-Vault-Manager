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

#ifndef MAIDSAFE_VAULT_MANAGER_NEW_CONNECTIONS_H_
#define MAIDSAFE_VAULT_MANAGER_NEW_CONNECTIONS_H_

#include <map>
#include <memory>

#include "asio/io_service.hpp"

#include "maidsafe/common/types.h"

#include "maidsafe/vault_manager/config.h"

namespace maidsafe {

namespace vault_manager {

class NewConnections : public std::enable_shared_from_this<NewConnections> {
 public:
  static std::shared_ptr<NewConnections> MakeShared(asio::io_service& io_service);
  ~NewConnections();
  void Add(tcp::ConnectionPtr connection);
  bool Remove(tcp::ConnectionPtr connection);
  void CloseAll();

 private:
  explicit NewConnections(asio::io_service& io_service);

  asio::io_service& io_service_;
  std::map<tcp::ConnectionPtr, TimerPtr, std::owner_less<tcp::ConnectionPtr>> connections_;
};

}  // namespace vault_manager

}  // namespace maidsafe

#endif  // MAIDSAFE_VAULT_MANAGER_NEW_CONNECTIONS_H_
