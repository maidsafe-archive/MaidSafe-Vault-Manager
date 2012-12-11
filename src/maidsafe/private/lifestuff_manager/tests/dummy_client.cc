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

#include "maidsafe/private/data_types/fob.h"
#include "maidsafe/private/lifestuff_manager/client_controller.h"


int main(int argc, char** argv) {
  maidsafe::log::Logging::Instance().Initialise(argc, argv);
  maidsafe::priv::lifestuff_manager::ClientController client(
      [](const maidsafe::NonEmptyString&){});  // NOLINT (Fraser)
  std::string account_name(maidsafe::RandomAlphaNumericString(16));
  maidsafe::Fob fob;
  try {
    if (!client.StartVault(fob, account_name, "")) {
      LOG(kError) << "dummy_client: Failed to start vault " << fob.identity().string();
    }
  } catch(...) {
    LOG(kError) << "dummy_client: Problem starting vault " << fob.identity().string();
  }
  LOG(kInfo) << "Identity: " << maidsafe::Base64Substr(fob.identity());
  LOG(kInfo) << "Validation Token: " << maidsafe::Base64Substr(fob.validation_token());
  LOG(kInfo) << "Public Key: "
             << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(fob.public_key()));
  LOG(kInfo) << "Private Key: "
             << maidsafe::Base64Substr(maidsafe::asymm::EncodeKey(fob.private_key()));
  LOG(kInfo) << "Account name: " << account_name;
  return 0;
}
