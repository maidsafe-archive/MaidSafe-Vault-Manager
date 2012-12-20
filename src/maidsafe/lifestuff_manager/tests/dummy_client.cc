/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include <iostream>

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"

#include "maidsafe/lifestuff_manager/client_controller.h"


int main(int argc, char** argv) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  maidsafe::lifestuff_manager::ClientController client(
      [](const maidsafe::NonEmptyString&){});  // NOLINT (Fraser)
  std::string account_name(maidsafe::RandomAlphaNumericString(16));
  maidsafe::passport::Anmaid anmaid;
  maidsafe::passport::Maid maid(anmaid);
  maidsafe::passport::Pmid pmid(maid);
  try {
    if (!client.StartVault(pmid, account_name, "")) {
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
  LOG(kInfo) << "Account name: " << account_name;
  return 0;
}
