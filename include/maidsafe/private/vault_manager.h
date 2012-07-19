/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#ifndef MAIDSAFE_PRIVATE_VAULT_MANAGER_H_
#define MAIDSAFE_PRIVATE_VAULT_MANAGER_H_

#include <string>
#include <vector>
#include <utility>

#include "maidsafe/private/process_manager.h"
#include "maidsafe/private/download_manager.h"
#include "boost/filesystem/fstream.hpp"
#include "boost/filesystem/operations.hpp"

class R;
class R;
namespace maidsafe {

namespace priv {

namespace bai = boost::asio::ip;

enum class VaultManagerMessageType {
  kHelloFromClient = 1,
  kHelloResponseToClient = 2,
  kStartRequestFromClient = 3,
  kIdentityInfoRequestFromVault = 4,
  kIdentityInfoToVault = 5
};

class VaultManager {
 public:
  VaultManager();
  VaultManager(const maidsafe::priv::VaultManager&);
  ~VaultManager();
  void RunVault(std::string chunkstore_path, std::string chunkstore_capacity, bool new_vault);
  bool ReadConfig();
  void StopVault(int32_t id);
  void EraseVault(int32_t id);
  int32_t ListVaults(bool select);
  void RestartVault(std::string id);
  int32_t get_process_vector_size();
  void ListenForUpdates();
  void ListenForMessages();
  void MessageHandler(int type, std::string payload);
  std::pair<std::string, std::string> FindLatestLocalVersion(std::string name,
                                                             std::string platform,
                                                             std::string cpu_size);

 private:
//   It should be decided if the following three methods are going to be private or public
//   void RunVault(/*std::string chunkstore_path, */std::string chunkstore_capacity,
//                     bool new_vault);
//   void StopVault();
//   bool ReadConfig();
  bool WriteConfig();
  std::vector<std::string> p_id_vector_;
  std::vector<maidsafe::Process> process_vector_;
  maidsafe::ProcessManager manager_;
  maidsafe::DownloadManager download_manager_;
  boost::asio::io_service io_service_;
//   bai::tcp::acceptor acceptor_;
//   bai::tcp::socket socket_;
};

}  // namespace private

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_VAULT_MANAGER_H_
