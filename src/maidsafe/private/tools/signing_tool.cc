/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#include "maidsafe/private/cli.h"

#include <fstream>
#include <iostream>
#include <istream>
#include <ostream>
#include <string>
#include <vector>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include "boost/program_options.hpp"
#include "boost/filesystem.hpp"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"


namespace fs = boost::filesystem;
namespace po = boost::program_options;

boost::program_options::options_description desc;
static maidsafe::rsa::Keys Keys;
static bool have_private_key(false);
static bool have_public_key(false);
static bool in_cli(false);

void CreateKeys(std::string) {
  std::cout << "Creating keys \nPlease wait !!\n";
  maidsafe::rsa::GenerateKeyPair(&Keys);
  have_public_key = true;
  have_private_key = true;
}

void SavePrivateKey(std::string filename) {
  if (!have_private_key) {
    std::cout << "You have not loaded or created a Private Key\nAborting!\n";
  }else {
    fs::path file(filename);
    std::string priv_key;
    maidsafe::rsa::EncodePrivateKey(Keys.private_key, &priv_key);
    if (!maidsafe::WriteFile(file, priv_key))
      std::cout << "error writing file\n";
    else
      std::cout << "Stored private key in " << filename << "\n";
  }
}

void SavePublicKey(std::string filename) {
  if (!have_public_key) {
    std::cout << "You have not loaded or created a Public Key\nAborting!\n";
  }else {
    fs::path file(filename);
    std::string pub_key;
    maidsafe::rsa::EncodePublicKey(Keys.public_key, &pub_key);
    if (!maidsafe::WriteFile(file, pub_key))
      std::cout << "error writing file\n";
    else
      std::cout << "Stored private key in " << filename << "\n";
  }
}

void LoadPrivateKey(std::string filename) {
    fs::path file(filename);
    std::string priv_key;
    if (!maidsafe::ReadFile(file, &priv_key)) {
      std::cout << "error reading file\n";
      return;
    }
    maidsafe::rsa::DecodePrivateKey(priv_key, &Keys.private_key);

    if (maidsafe::rsa::ValidateKey(Keys.private_key))
      std::cout << "private key loaded and valid \n";
    else
      std::cout << "private key invalid !! \n";
}

void LoadPublicKey(std::string filename) {
    fs::path file(filename);
    std::string pub_key;
    if (!maidsafe::ReadFile(file, &pub_key)) {
      std::cout << "error reading file\n";
      return;
    }
    maidsafe::rsa::DecodePublicKey(pub_key, &Keys.public_key);

    if (maidsafe::rsa::ValidateKey(Keys.public_key))
      std::cout << "public key loaded and valid \n";
    else
      std::cout << "public key invalid !! \n";
}

void SignFile(std::string filename) {
  fs::path file(filename);
  std::string data, signature;
  if (!maidsafe::ReadFile(file, &data)) {
    std::cout << "error reading file\n";
    return;
  }
  if (!maidsafe::rsa::ValidateKey(Keys.private_key)) {
    std::cout << "private key invalid, aborting!!\n";
  }

  if (maidsafe::rsa::Sign(data, Keys.private_key, &signature) != 0) {
    std::cout << "cannot sign data, aborting\n";
    return;
  }
  fs::path sigfile(filename + ".sig");
  if (!maidsafe::WriteFile(sigfile, signature))
    std::cout << "error writing file\n";
  else
    std::cout << "Stored signature in " << sigfile << "\n";
}

void ValidateSignature(std::string filename) {
  fs::path file(filename);
  fs::path sigfile(filename + ".sig");

  std::string data, signature;
  if (!maidsafe::ReadFile(file, &data) || !maidsafe::ReadFile(sigfile, &signature)) {
    std::cout << "error reading file\n";
    return;
  }
  if (!maidsafe::rsa::ValidateKey(Keys.public_key)) {
    std::cout << "public key invalid, aborting!!\n";
  }

  if (maidsafe::rsa::CheckSignature(data, signature, Keys.public_key) == 0)  {
    std::cout << "Signature valid\n";
  } else {
    std::cout << "Invalid signature !! \n";
  }
}

std::string GetPasswd() {
  std::string passwd("r"), passwd2("s");
  while (passwd != passwd2) {
    std::cout << "please Enter passwd \n";
    std::getline(std::cin, passwd);
    std::cout << "please Re-Enter same passwd \n";
    std::getline(std::cin, passwd2);
  }
  return maidsafe::crypto::Hash<maidsafe::crypto::SHA512>(passwd);
}

void EncryptFile(std::string filename) {
  fs::path file(filename);
  std::string data;
  std::string passwd = GetPasswd();
  std::string key = passwd.substr(0, 32);
  std::string iv = passwd.substr(32, 48);

  if (!maidsafe::ReadFile(file, &data)) {
    std::cout << "error reading file\n";
    return;
  }

  if (!maidsafe::WriteFile(file, maidsafe::crypto::SymmEncrypt(data, key, iv)))
    std::cout << "error writing file\n";
  else
    std::cout << "File is now encrypted " << filename << "\n";
}

void DecryptFile(std::string filename) {
  fs::path file(filename);
  std::string data;
  std::string passwd = GetPasswd();
  std::string key = passwd.substr(0, 32);
  std::string iv = passwd.substr(32, 48);

  if (!maidsafe::ReadFile(file, &data)) {
    std::cout << "error reading file\n";
    return;
  }
  if (!maidsafe::WriteFile(file, maidsafe::crypto::SymmDecrypt(data, key, iv)))
    std::cout << "error writing file\n";
  else
    std::cout << "File is now decrypted " << filename << "\n";
}

void CreateKeyGroup(std::string ) {
  std::string total;
  std::cout << "please Enter total number of people \n";
  std::getline(std::cin, total);
  std::string quorum;
  std::cout << "please Enter number of people required to sign\n";
  std::getline(std::cin, quorum);
  int max = atoi(total.c_str());
  int min = atoi(quorum.c_str());

  if (max < min) {
    std::cout << "Y must be smaller or equal to X\n";
    return;
  }
  if (min < 2) {
    std::cout << "smallest required group is 2";
    return;
  }

  CreateKeys("");

  // create the chunks of the private key.
  std::string priv_key;
  maidsafe::rsa::EncodePrivateKey(Keys.private_key, &priv_key);
  std::vector<std::string> chunks;

  maidsafe::crypto::SecretShareData(min, max, priv_key, &chunks);

  std::map<std::string, std::string> users;
  std::pair<std::map<std::string, std::string>::iterator, bool> ret;
  for(int i =0; i < max; ++i) {
    std::string name;
    std::cout << "please Enter unique name \n";
    std::getline(std::cin, name);
    std::string passwd = GetPasswd();
    ret = users.insert(std::pair<std::string, std::string>(name, passwd));
    if (!ret.second) {
      std::cout << "Error, are you sure you used a unique name, retry !\n";
      --i;
    } else {
      std::string key = passwd.substr(0, 32);
      std::string iv = passwd.substr(32, 48);
      fs::path file(name + ".keyfile");
      if (!maidsafe::WriteFile(file, maidsafe::crypto::SymmEncrypt(chunks.at(i), key, iv))) {
        std::cout << "error writing file\n";
        --i;
        std::cout << "Error, are you sure you used a unique name, retry !\n";
      } else {
        std::cout << "File is now encrypted and saved as " << file.c_str() << "\n"
                  << "for " << name << "\n";
      }
    }
  }
  SavePublicKey("group_public_key.id");
}

void GroupSignIn(std::string) {
  std::string total;
  std::cout << "please Enter total number of people \n";
  std::getline(std::cin, total);
  std::string quorum;
  std::cout << "please Enter number of people required to sign\n";
  std::getline(std::cin, quorum);
  int max = atoi(total.c_str());
  int min = atoi(quorum.c_str());
  std::vector<std::string> chunks;
  std::string enc_data;
  std::string priv_key;

  for(int i =0; i < min; ++i) {
    enc_data.clear();
    std::string name;
    std::cout << "please Enter name \n";
    std::getline(std::cin, name);
    std::string passwd = GetPasswd();

    std::string key = passwd.substr(0, 32);
    std::string iv = passwd.substr(32, 48);
    fs::path file(name + ".keyfile");
    if (!maidsafe::ReadFile(file, &enc_data)) {
      std::cout << "error reading file\n";
      --i;
      std::cout << "Error, are you sure you used a correct name/password, retry !\n";
    } else {
      chunks.push_back(maidsafe::crypto::SymmDecrypt(enc_data, key, iv));
      //enc_data.clear();
    }
  }
  maidsafe::crypto::SecretRecoverData(min, chunks, &priv_key);
  maidsafe::rsa::DecodePrivateKey(priv_key, &Keys.private_key);

  if (maidsafe::rsa::ValidateKey(Keys.private_key))
    std::cout << "private key loaded and valid \n";
  else
    std::cout << "private key invalid !! \n";
}


void Exit(std::string)
{
  exit(0);
}

void help(std::string ) {
  if (in_cli) {
    std::cout << "MaidSafe Help \n"
              << "CreateKeys   \t \t \t Creates an RSA keypair (2048) \n"
              << "SavePrivateKey <out file name> \t Stores private key to file \n"
              << "SavePublicKey <out file name> \t Stores public key to file \n"
              << "LoadPrivateKey <in file name> \t Setrieve private key to file \n"
              << "LoadPublicKey <in file name> \t Retrieve public key to file \n"
              << "CreateKeyGroup \t\t Creates  a group of X people of whom Y are required to validate / sign data \n"
              << "GroupSignIn \t\t\t Y people will be required to sign in\n"
              << "SignFile <filename> \t\t Sign the file passed on command line\n"
              << "ValidateSignature <filename> \t Validate signature of file\n"
              << "EncryptFile <file> \t Encrypt (AES256) a file with this password\n"
              << "DecryptFile <file> \t Decrypt (AES256) a file with this password\n";
  } else {
    std::cout << "MaidSafe Help \n"
              << "============================================================================\n"
              << "EncryptFile <file>  <password>\t Encrypt (AES256) a file with this password\n"
              << "DecryptFile <file>  <password>\t Decrypt (AES256) a file with this password\n"
              << "\n"
              << "____________________________________________________________________________\n"
              << "use SigningTool --cli for a command line interface (more options) \n\n";
  }
}

int main(int argc, char **argv) {
  desc.add_options()
      ("help", po::value<std::string>()->notifier(&help)->implicit_value(""))
      ("cli", "command line")
      ("CreateKeys", po::value<std::string>()->notifier(&CreateKeys)->implicit_value(""))
      ("SavePrivateKey", po::value<std::string>()->notifier(&SavePrivateKey))
      ("SavePublicKey", po::value<std::string>()->notifier(&SavePublicKey))
      ("LoadPrivateKey", po::value<std::string>()->notifier(&LoadPrivateKey))
      ("LoadPublicKey", po::value<std::string>()->notifier(&LoadPublicKey))
      ("SignFile", po::value<std::string>()->notifier(&SignFile))
      ("ValidateSignature", po::value<std::string>()->notifier(&ValidateSignature))
      ("EncryptFile", po::value<std::string>()->notifier(&EncryptFile))
      ("DecryptFile", po::value<std::string>()->notifier(&DecryptFile))
      ("CreateKeyGroup", po::value<std::string>()->notifier(&CreateKeyGroup)->implicit_value(""))
      ("GroupSignIn", po::value<std::string>()->notifier(&GroupSignIn)->implicit_value(""))
      ("exit", po::value<std::string>()->notifier(&Exit)->implicit_value(""))
      ("quit", po::value<std::string>()->notifier(&Exit)->implicit_value(""));

  try {
    po::variables_map vm1;
    po::store(po::parse_command_line(argc, argv, desc), vm1);
    po::notify(vm1);
    maidsafe::Cli cli(desc);
    if (vm1.count("cli")) {
      in_cli = true;
      cli.Run(std::cin);
    }
  } catch (po::error  &e) {
    std::cerr << "error: " << e.what() << std::endl;
  }
  if (!in_cli)
    help("");

}



