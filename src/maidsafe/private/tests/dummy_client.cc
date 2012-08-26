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

#include "maidsafe/private/process_management/client_controller.h"


int main(int /*ac*/, char* /*av*/[]) {
  maidsafe::priv::process_management::ClientController client;
  maidsafe::asymm::Keys keys;
  std::string account_name("ACCOUNT1");
  maidsafe::asymm::GenerateKeyPair(&keys);
  keys.identity = maidsafe::RandomAlphaNumericString(64);
  keys.validation_token = maidsafe::RandomAlphaNumericString(64);
  try {
  client.StartVault(keys, account_name/*,
                    boost::asio::ip::udp::endpoint(
                        boost::asio::ip::address::from_string("127.0.0.1"), 5483)*/);
  } catch(...) {
    LOG(kError) << "DUMMYclient: Problem starting vault " << (keys.identity);
  }
  LOG(kInfo) << "Identity: " << (keys.identity);
  LOG(kInfo) << "Validation Token: " << (keys.validation_token);
  std::string public_key_string;
  maidsafe::asymm::EncodePublicKey(keys.public_key, &public_key_string);
  std::string private_key_string;
  maidsafe::asymm::EncodePrivateKey(keys.private_key, &private_key_string);
  LOG(kInfo) << "Public Key: " << maidsafe::Base64Substr(public_key_string);
  LOG(kInfo) << "Private Key: " << maidsafe::Base64Substr(private_key_string);
  LOG(kInfo) << "Account name: " << account_name;
  return 0;
}
