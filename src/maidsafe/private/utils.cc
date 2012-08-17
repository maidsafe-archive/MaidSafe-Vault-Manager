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

#include "maidsafe/private/utils.h"

#include <cstdint>
#include <iterator>

#include "boost/lexical_cast.hpp"
#include "boost/tokenizer.hpp"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/controller_messages_pb.h"
#include "maidsafe/private/local_tcp_transport.h"
#include "maidsafe/private/process_manager.h"
#include "maidsafe/private/vault_manager.h"


namespace maidsafe {

namespace priv {

namespace detail {

namespace {

char key[268] = { '\x30', '\x82', '\x01', '\x08', '\x02', '\x82', '\x01', '\x01', '\x00', '\xe9',
                  '\x7d', '\x80', '\x92', '\x35', '\x86', '\xb7', '\xac', '\x2c', '\x72', '\xb8',
                  '\x08', '\x75', '\x98', '\xaf', '\x9b', '\xd0', '\x54', '\x24', '\x98', '\x79',
                  '\xb8', '\xd9', '\x9c', '\x24', '\x9a', '\xf0', '\x5a', '\xe4', '\x33', '\x8d',
                  '\xcd', '\x96', '\x9c', '\x44', '\x0a', '\x39', '\xa7', '\x9d', '\x8c', '\xab',
                  '\xa3', '\x4a', '\x7b', '\xc5', '\x57', '\x1e', '\x92', '\x55', '\x7c', '\x1e',
                  '\xde', '\x11', '\xd4', '\x8b', '\xa3', '\x4d', '\xc4', '\x64', '\xb7', '\xf7',
                  '\xf3', '\x58', '\x09', '\x2d', '\x39', '\x16', '\x22', '\xa2', '\xa2', '\x0c',
                  '\x18', '\x3d', '\x6f', '\x29', '\x69', '\x82', '\x7e', '\x53', '\x7e', '\x6d',
                  '\xd6', '\x50', '\xf7', '\xf1', '\x7c', '\xfa', '\x9c', '\xa8', '\xb3', '\xe9',
                  '\x0b', '\x86', '\x21', '\x2e', '\x07', '\x18', '\x85', '\x54', '\x68', '\x28',
                  '\x6d', '\x35', '\x3d', '\x02', '\x79', '\xe6', '\xcb', '\xdc', '\x70', '\xb3',
                  '\x38', '\xfa', '\x56', '\x36', '\x2b', '\x15', '\xc7', '\x53', '\x4e', '\x2e',
                  '\xe1', '\xff', '\x62', '\x71', '\xc8', '\xa9', '\x8b', '\x09', '\xf7', '\xba',
                  '\xb1', '\x6c', '\x47', '\x57', '\x68', '\x26', '\xae', '\xfa', '\x24', '\x85',
                  '\x72', '\x0c', '\x0b', '\xf3', '\x0c', '\x28', '\xde', '\xb5', '\xd5', '\xeb',
                  '\x58', '\x3f', '\xdf', '\xb3', '\xb4', '\x18', '\x2f', '\x4b', '\xa8', '\x3b',
                  '\x7b', '\x00', '\x4d', '\x41', '\x4b', '\xf7', '\xae', '\x4c', '\x54', '\x40',
                  '\x2e', '\xd8', '\x60', '\x64', '\x09', '\x6b', '\xa2', '\xce', '\xc0', '\x2f',
                  '\xca', '\xf3', '\x36', '\x8c', '\x9b', '\x04', '\x70', '\x0e', '\x5e', '\x7a',
                  '\x55', '\xf2', '\xd1', '\x62', '\x86', '\xad', '\x89', '\x0d', '\x7c', '\x39',
                  '\x39', '\x5a', '\x04', '\xcc', '\xd2', '\x7f', '\x73', '\x02', '\xff', '\x55',
                  '\xba', '\x5e', '\xea', '\x4f', '\x5a', '\xe9', '\xd8', '\x13', '\x71', '\xdb',
                  '\x9b', '\xb3', '\x2d', '\xcb', '\xec', '\xca', '\x9a', '\x1f', '\x96', '\xc6',
                  '\xa5', '\x8b', '\xd9', '\xb6', '\x3e', '\x2b', '\xfc', '\xf8', '\x9e', '\xca',
                  '\xf1', '\xb2', '\xb0', '\xd2', '\x9e', '\x79', '\x88', '\x92', '\x96', '\x8d',
                  '\x0f', '\x00', '\x57', '\xe1', '\x77', '\x02', '\x01', '\x11' };

const char kSeparator('_');

}  // unnamed namespace

const int kInvalidVersion(-1);
const std::string kSignatureExtension(".sig");
const std::string kMaidSafePublicKey(key, 268);


Platform::Platform(const Platform::Type& type) : type_(type), name_() {
  switch (type) {
    case Type::kWin32:
      name_ = kWinStr() + "32";
      break;
    case Type::kWin64:
      name_ = kWinStr() + "64";
      break;
    case Type::kLinux32:
      name_ = kLinuxStr() + "32";
      break;
    case Type::kLinux64:
      name_ = kLinuxStr() + "64";
      break;
    case Type::kOsx32:
      name_ = kOsxStr() + "32";
      break;
    case Type::kOsx64:
      name_ = kOsxStr() + "64";
      break;
    default:
      type_ = Type::kUnknown;
      break;
  }
}

Platform::Platform(const std::string& name) : type_(Type::kUnknown), name_(name) {
  if (name_ == kWinStr() + "32")
    type_ = Type::kWin32;
  else if (name_ == kWinStr() + "64")
    type_ = Type::kWin64;
  else if (name_ == kLinuxStr() + "32")
    type_ = Type::kLinux32;
  else if (name_ == kLinuxStr() + "64")
    type_ = Type::kLinux64;
  else if (name_ == kOsxStr() + "32")
    type_ = Type::kOsx32;
  else if (name_ == kOsxStr() + "64")
    type_ = Type::kOsx64;
  else
    name_.clear();
}

Platform::Platform() : type_(Type::kUnknown), name_() {
  int32_t cpu_size(CpuSize());
#if defined MAIDSAFE_WIN32
  if (cpu_size == 32) {
    name_ = kWinStr() + "32";
    type_ = Type::kWin32;
  } else if (cpu_size == 64) {
    name_ = kWinStr() + "64";
    type_ = Type::kWin64;
  }
#elif defined MAIDSAFE_LINUX
  if (cpu_size == 32) {
    name_ = kLinuxStr() + "32";
    type_ = Type::kLinux32;
  } else if (cpu_size == 64) {
    name_ = kLinuxStr() + "64";
    type_ = Type::kLinux64;
  }
#elif defined MAIDSAFE_APPLE
  if (cpu_size == 32) {
    name_ = kOsxStr() + "32";
    type_ = Type::kOsx32;
  } else if (cpu_size == 64) {
    name_ = kOsxStr() + "64";
    type_ = Type::kOsx64;
  }
#endif
}

std::string Platform::executable_extension() const {
  return (type_ == Type::kWin32 || type_ == Type::kWin64) ? ".exe" : "";
}

std::string Platform::installer_extension() const {
  return (type_ == Type::kWin32 || type_ == Type::kWin64) ? ".exe" : ".deb";
}

Platform kThisPlatform() {
  static Platform this_platform;
  return this_platform;
}


std::string WrapMessage(const MessageType& message_type,
                        const std::string& payload) {
  protobuf::WrapperMessage wrapper_message;
  wrapper_message.set_type(static_cast<int>(message_type));
  wrapper_message.set_payload(payload);
  return wrapper_message.SerializeAsString();
}

bool UnwrapMessage(const std::string& wrapped_message,
                   MessageType& message_type,
                   std::string& payload) {
  protobuf::WrapperMessage wrapper;
  if (wrapper.ParseFromString(wrapped_message) && wrapper.IsInitialized()) {
    message_type = static_cast<MessageType>(wrapper.type());
    payload = wrapper.payload();
    return true;
  } else {
    LOG(kError) << "Failed to unwrap message";
    message_type = static_cast<MessageType>(0);
    payload.clear();
    return false;
  }
}

std::string VersionToString(int version,
                            std::string* major_version,
                            std::string* minor_version,
                            std::string* patch_version) {
  if (version < 0)
    return "";

  std::string full_version(boost::lexical_cast<std::string>(version));
  size_t padding_count(6 - full_version.size());
  full_version.insert(0, padding_count, '0');
  std::string major_ver(full_version.substr(0, 2));
  std::string minor_ver(full_version.substr(2, 2));
  std::string patch_ver(full_version.substr(4, 2));

  if (major_ver.at(0) == '0')
    major_ver.assign(major_ver.substr(1, 1));
  if (major_version)
    *major_version = major_ver;
  if (minor_version)
    *minor_version = minor_ver;
  if (patch_version)
    *patch_version = patch_ver;
  return major_ver + "." + minor_ver + "." + patch_ver;
}

int VersionToInt(const std::string& version) {
  boost::tokenizer<boost::char_separator<char>> tokens(version, boost::char_separator<char>("."));
  if (std::distance(tokens.begin(), tokens.end()) != 3)
    return kInvalidVersion;

  auto itr(tokens.begin());

  int16_t major_version(0), minor_version(0), patch_level(0);
  try {
    major_version = boost::lexical_cast<int16_t>(*(itr++));

    minor_version = boost::lexical_cast<int16_t>(*itr);
    if ((*itr++).size() != 2U) {
      LOG(kWarning) << "Invalid minor version " << version;
      return kInvalidVersion;
    }

    patch_level = boost::lexical_cast<int16_t>(*itr);
    if ((*itr++).size() != 2U) {
      LOG(kWarning) << "Invalid patch level " << version;
      return kInvalidVersion;
    }
  }
  catch(const boost::bad_lexical_cast& e) {
    LOG(kWarning) << "Invalid version " << version << ": " << e.what();
    return kInvalidVersion;
  }

  if (major_version < 0 || minor_version < 0 || patch_level < 0) {
    LOG(kWarning) << "Invalid version " << version;
    return kInvalidVersion;
  }

  return (major_version * 10000) + (minor_version * 100) + patch_level;
}

std::string GenerateFileName(const std::string& application,
                             const Platform& platform,
                             const std::string& version) {
  if (application.empty()) {
    LOG(kError) << "application is empty.";
    return "";
  }

  if (platform.type() == Platform::Type::kUnknown) {
    LOG(kError) << "platform type unknown.";
    return "";
  }

  if (VersionToInt(version) == kInvalidVersion) {
    LOG(kError) << '\"' << version << "\" is an invalid version.";
    return "";
  }

  return application + kSeparator + platform.name() + kSeparator + version +
         platform.executable_extension();
}

bool TokeniseFileName(const std::string& file_name,
                      std::string* application,
                      Platform* platform,
                      int* version,
                      std::string* extension) {
  auto fail([&]()->bool {
    if (application)
      application->clear();
    if (platform)
      *platform = Platform(Platform::Type::kUnknown);
    if (version)
      *version = kInvalidVersion;
    if (extension)
      extension->clear();
    return false;
  });

  boost::tokenizer<boost::char_separator<char>> tokens(file_name,
                                                       boost::char_separator<char>("_"));
  if (std::distance(tokens.begin(), tokens.end()) != 3) {
    LOG(kWarning) << "Invalid file name " << file_name;
    return fail();
  }

  auto itr(tokens.begin());
  const std::string kApplication(*itr++);
  if (kApplication.empty()) {
    LOG(kWarning) << "application name empty in " << file_name;
    return fail();
  }

  const Platform kPlatform(*itr);
  if (kPlatform.type() == Platform::Type::kUnknown) {
    LOG(kWarning) << "Invalid platform of \"" << (*itr) << "\" in " << file_name;
    return fail();
  }
  ++itr;

  const std::string kVersionAndExtension(*itr);
  int versn(VersionToInt(kVersionAndExtension));
  std::string extnsn;
  if (versn == kInvalidVersion) {
    size_t last_dot_pos(kVersionAndExtension.find_last_of("."));
    versn = VersionToInt(kVersionAndExtension.substr(0, last_dot_pos));
    if (versn == kInvalidVersion) {
      LOG(kWarning) << "Invalid version of \"" << kVersionAndExtension.substr(0, last_dot_pos)
                    << "\" in " << file_name;
      return fail();
    }
    extnsn = kVersionAndExtension.substr(last_dot_pos);
    if (extnsn != kPlatform.executable_extension()) {
      LOG(kWarning) << "Invalid executable extension of \"" << extnsn << "\" in " << file_name;
      return fail();
    }
  }

  if (application)
    *application = kApplication;
  if (platform)
    *platform = kPlatform;
  if (version)
    *version = versn;
  if (extension)
    *extension = extnsn;
  return true;
}

std::string GenerateVmidParameter(const ProcessIndex& process_index,
                                  const Port& vault_manager_port) {
  return boost::lexical_cast<std::string>(process_index) + kSeparator +
         boost::lexical_cast<std::string>(vault_manager_port);
}

bool ParseVmidParameter(const std::string& vault_manager_identifier,
                        ProcessIndex& process_index,
                        Port& vault_manager_port) {
  auto do_fail([&]()->bool {
    process_index = vault_manager_port = 0;
    return false;
  });

  size_t separator_position(vault_manager_identifier.find(kSeparator));
  if (separator_position == std::string::npos) {
    LOG(kError) << "vault_manager_identifier " << vault_manager_identifier << " has wrong format";
    return do_fail();
  }
  try {
    process_index =
        boost::lexical_cast<ProcessIndex>(vault_manager_identifier.substr(0, separator_position));
    vault_manager_port =
        boost::lexical_cast<Port>(vault_manager_identifier.substr(separator_position + 1));
  }
  catch(const boost::bad_lexical_cast& exception) {
    LOG(kError) << "vault_manager_identifier " << vault_manager_identifier << " has wrong format: "
                << exception.what();
    return do_fail();
  }

  if (process_index == 0) {
    LOG(kError) << "Invalid process index of 0";
    return do_fail();
  }

  if (vault_manager_port < VaultManager::kMinPort() ||
      vault_manager_port > VaultManager::kMaxPort()) {
    LOG(kError) << "Invalid Vault Manager port " << vault_manager_port;
    return do_fail();
  }

  return true;
}

}  // namespace detail

}  //  namespace priv

}  //  namespace maidsafe
