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

#include "maidsafe/private/cli_menu.h"
#ifdef WIN32
#include <windows.h>
#else
#include <termio.h>
#include <unistd.h>
#endif
#include <fstream>
#include <iostream>
#include <istream>
#include <ostream>
#include <string>
#include <vector>
#include "boost/filesystem.hpp"
#include "maidsafe/common/utils.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"

static std::string prompt(">> ");
static maidsafe::rsa::Keys Keys;
static bool have_private_key(false);
static bool have_public_key(false);

template <class T>
T Get(std::string display_message, bool echo_input = true);


void Echo(bool enable = true) {
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if( !enable )
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode );

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if( !enable )
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

std::string GetPasswd() {
  std::string passwd("r"), passwd2("s");
  Echo(false);
  while (passwd != passwd2) {
    std::cout << "please Enter passwd \n";
    std::getline(std::cin, passwd);
    std::cout << "please Re-Enter same passwd \n";
    std::getline(std::cin, passwd2);
  }
  Echo(true);
  return maidsafe::crypto::Hash<maidsafe::crypto::SHA512>(passwd);
}

std::vector<std::string> TokeniseLine(std::string line)  {
  std::vector<std::string> args;
  line = std::string("--") + line;
  boost::char_separator<char> sep(" ");
  boost::tokenizer< boost::char_separator<char> > tokens(line, sep);
  for (const auto& t : tokens) {
    args.push_back(t);
  }
}

void CreateKeys() {
  std::cout << "Creating keys \nPlease wait !!\n";
  maidsafe::rsa::GenerateKeyPair(&Keys);
  have_public_key = true;
  have_private_key = true;
  std::cout << "Creating keys sucessful\n";
}

void SavePrivateKey() {
  std::string filename = Get<std::string>("please enter filename");
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

void SavePublicKey() {
  std::string filename = Get<std::string>("please enter filename to save to\n");
  if (!have_public_key) {
    std::cout << "You have not loaded or created a Public Key\nAborting!\n";
  }else {
    fs::path file(filename);
    std::string pub_key;
    maidsafe::rsa::EncodePublicKey(Keys.public_key, &pub_key);
    if (!maidsafe::WriteFile(file, pub_key))
      std::cout << "error writing file\n";
    else
      std::cout << "Stored public key in " << filename << "\n";
  }
}

void LoadPrivateKey() {
  std::string filename = Get<std::string>("please enter filename");
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

void LoadPublicKey() {
  std::string filename = Get<std::string>("please enter filename");
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

void SignFile() {
  std::string filename = Get<std::string>("please enter filename");
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

void ValidateSignature() {
  std::string filename = Get<std::string>("please enter filename");
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

void EncryptFile() {
  std::string filename = Get<std::string>("please enter filename");
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

void DecryptFile() {
  std::string filename = Get<std::string>("please enter filename");
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

void CreateKeyGroup() {
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
  if (!have_private_key) {
    std::cout << " No Private key found, creating now\n";
    CreateKeys();
    std::cout << " You can still load another private key from disk if you wish\n";
  }

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
    if (i < max - 1)
      std::cout << "Password Sucessfull next person please\n ==================================\n";
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
  SavePublicKey();
}

void GroupSignIn() {
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
     if (i < max - 1)
      std::cout << "Password captured next person please\n ==================================\n";
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


void Exit() {
  exit(0);
}

void Help() {
  std::cout << "MaidSafe Help \n ________________________________________________\n"
            << "1: CreateKeys   \t \t Creates an RSA keypair (2048) \n"
            << "2: SavePrivateKey \t\t Stores private key to file \n"
            << "3: SavePublicKey \t\t Stores public key to file \n"
            << "4: LoadPrivateKey \t\t Setrieve private key to file \n"
            << "5: LoadPublicKey \t\t Retrieve public key to file \n"
            << "6: CreateKeyGroup \t\t X people of whom Y are required to manage keys \n"
            << "7: GroupSignIn    \t\t Y Sign in and load private key\n"
            << "8: SignFile <filename> \t\t Sign the file passed on command line\n"
            << "9: ValidateSignature \t\t Validate signature of file\n"
            << "10: EncryptFile <file> \t\t Encrypt (AES256) a file\n"
            << "11: DecryptFile <file> \t\t Decrypt (AES256) a file\n"
            << "0: Exit the system;";
}

void Process(int command) {
  switch (command) {
  case 0:
    Exit();
    break;
  case 1:
    CreateKeys();
    break;
  case 2:
    SavePrivateKey();
    break;
  case 3:
    SavePublicKey();
    break;
  case 4:
    LoadPrivateKey();
    break;
  case 5:
    LoadPublicKey();
    break;
  case 6:
    CreateKeyGroup();
    break;
  case 7:
    GroupSignIn();
    break;
  case 8:
    SignFile();
    break;
  case 9:
    ValidateSignature();
    break;
  case 10:
    EncryptFile();
    break;
  case 11:
    DecryptFile();
    break;
  default :
    std::cout << "unknown option \n";
    std::cout << prompt << std::flush;
    Help();
  }
}

template <class T>
T Get(std::string display_message, bool echo_input) {
  Echo(echo_input);
  std::cout << display_message << "\n";
  std::cout << prompt << std::flush;
  T command;
  std::string input;
  while (std::getline(std::cin, input, '\n')) {
    std::cout << prompt << std::flush;
    if (std::stringstream(input) >> command) {
      Echo(true);
      return command;
    } else {
      Echo(true);
      std::cout << "invalid option\n";
      std::cout << prompt << std::flush;
    }
  }
}

int main() {
  while(true) {
  Echo(true);
    std::cout << "=======================================\n";
    Help();
    Process(Get<int>("", true));
    std::cout << "=======================================\n";
  }
}


