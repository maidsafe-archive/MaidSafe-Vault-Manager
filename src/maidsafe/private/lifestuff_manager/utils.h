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

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_UTILS_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_UTILS_H_

#include <cstdint>
#include <string>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/rsa.h"


namespace maidsafe {

namespace priv {

namespace lifestuff_manager {

enum class MessageType;

namespace detail {

class Platform {
 public:
  enum class Type { kWin32, kWin64, kLinux32, kLinux64, kOsx32, kOsx64, kUnknown };
  explicit Platform(const Type& type);
  explicit Platform(const std::string& name);
  Type type() const { return type_; }
  std::string name() const { return name_; }
  static std::string kWinStr() { return "win"; }
  static std::string kLinuxStr() { return "linux"; }
  static std::string kOsxStr() { return "osx"; }
  // Returns ".exe" for Windows, else an empty string.
  std::string executable_extension() const;
  std::string installer_extension() const;
  boost::filesystem::path UpdatePath() const;
  friend Platform kThisPlatform();
 private:
  // Default constructs Platform using host machine's details.
  Platform();
  Type type_;
  std::string name_;
};

asymm::PublicKey kMaidSafePublicKey();

Platform kThisPlatform();

std::string WrapMessage(const MessageType& message_type, const std::string& payload);

bool UnwrapMessage(const std::string& wrapped_message,
                   MessageType& message_type,
                   std::string& payload);

// Concatenates the components, placing an underscore between application, platform and version.
// If platform is kUnknown, or version is invalid, then an empty string is returned.
std::string GenerateFileName(const std::string& application,
                             const Platform& platform,
                             const std::string& version);

bool TokeniseFileName(const std::string& file_name,
                      std::string* application = nullptr,
                      Platform* platform = nullptr,
                      int* version = nullptr,
                      std::string* extension = nullptr);

// Returns a string which can be used as the --vmid argument of the PD vault.
std::string GenerateVmidParameter(const uint32_t& process_index,
                                  const uint16_t& lifestuff_manager_port);

// Parses a --vmid argument of the PD vault into its constituent parts.
bool ParseVmidParameter(const std::string& lifestuff_manager_identifier,
                        uint32_t& process_index,
                        uint16_t& lifestuff_manager_port);

uint16_t GetRandomPort();

bool GenerateFakeBootstrapFile(const int& number_of_entries);

}  // namespace detail

}  // namespace lifestuff_manager

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_UTILS_H_
