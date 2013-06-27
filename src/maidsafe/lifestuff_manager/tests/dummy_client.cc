/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/



#include <iostream>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/lifestuff_manager/client_controller.h"


int main(int argc, char** argv) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  maidsafe::lifestuff_manager::ClientController client([](const std::string&) {});
  std::string account_name(maidsafe::RandomAlphaNumericString(16));
  maidsafe::passport::Anmaid anmaid;
  maidsafe::passport::Maid maid(anmaid);
  maidsafe::passport::Pmid pmid(maid);
  try {
    if (!client.StartVault(pmid, maid.name(), "")) {
      LOG(kError) << "dummy_client: Failed to start vault " << pmid.name().data.string();
    }
  } catch(...) {
    LOG(kError) << "dummy_client: Problem starting vault " << pmid.name().data.string();
  }
  LOG(kInfo) << "Identity: " << maidsafe::Base64Substr(pmid.name().data.string());
  LOG(kInfo) << "Validation Token: " << maidsafe::Base64Substr(pmid.validation_token());
  LOG(kInfo) << "Public Key: "
             << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(pmid.public_key()));
  LOG(kInfo) << "Private Key: "
             << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(pmid.private_key()));
  LOG(kInfo) << "Account name: " << maidsafe::Base64Substr(maid.name()->string());
  return 0;
}
