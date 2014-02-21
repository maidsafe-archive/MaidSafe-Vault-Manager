/*  Copyright 2012 MaidSafe.net limited

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

#include <iostream>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/client_manager/client_controller.h"

int main(int argc, char** argv) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  maidsafe::client_manager::ClientController client([](const std::string&) {});
  std::string account_name(maidsafe::RandomAlphaNumericString(16));
  maidsafe::passport::Anmaid anmaid;
  maidsafe::passport::Maid maid(anmaid);
  maidsafe::passport::Pmid pmid(maid);
  try {
    if (!client.StartVault(pmid, maid.name(), "")) {
      LOG(kError) << "dummy_client: Failed to start vault " << pmid.name()->string();
    }
  }
  catch (...) {
    LOG(kError) << "dummy_client: Problem starting vault " << pmid.name()->string();
  }
  LOG(kInfo) << "Identity: " << maidsafe::Base64Substr(pmid.name()->string());
  LOG(kInfo) << "Validation Token: " << maidsafe::Base64Substr(pmid.validation_token());
  LOG(kInfo) << "Public Key: "
             << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(pmid.public_key()));
  LOG(kInfo) << "Private Key: "
             << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(pmid.private_key()));
  LOG(kInfo) << "Account name: " << maidsafe::Base64Substr(maid.name()->string());
  return 0;
}
