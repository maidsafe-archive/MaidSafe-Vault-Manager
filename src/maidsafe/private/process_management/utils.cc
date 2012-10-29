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

#include "maidsafe/private/process_management/utils.h"

#include <cstdint>
#include <iterator>
#include <set>

#include "boost/lexical_cast.hpp"
#include "boost/tokenizer.hpp"
#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/process_management/controller_messages_pb.h"
#include "maidsafe/private/process_management/local_tcp_transport.h"
#include "maidsafe/private/process_management/process_manager.h"
#include "maidsafe/private/process_management/invigilator.h"


namespace maidsafe {

namespace priv {

namespace process_management {

namespace detail {

namespace {

const char kSeparator('_');

}  // unnamed namespace

const std::string kSignatureExtension(".sig");

asymm::PublicKey kMaidSafePublicKey() {
  static auto const decoded_key = asymm::DecodeKey(asymm::EncodedPublicKey(DecodeFromHex("308201080282010100e97d80923586b7ac2c72b8087598af9bd054249879b8d99c249af05ae4338dcd969c440a39a79d8caba34a7bc5571e92557c1ede11d48ba34dc464b7f7f358092d391622a2a20c183d6f2969827e537e6dd650f7f17cfa9ca8b3e90b86212e0718855468286d353d0279e6cbdc70b338fa56362b15c7534e2ee1ff6271c8a98b09f7bab16c47576826aefa2485720c0bf30c28deb5d5eb583fdfb3b4182f4ba83b7b004d414bf7ae4c54402ed86064096ba2cec02fcaf3368c9b04700e5e7a55f2d16286ad890d7c39395a04ccd27f7302ff55ba5eea4f5ae9d81371db9bb32dcbecca9a1f96c6a58bd9b63e2bfcf89ecaf1b2b0d29e798892968d0f0057e177020111")));
  return decoded_key;
}

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

boost::filesystem::path Platform::UpdatePath() const {
  return boost::filesystem::path(name_);
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
                                  const Port& invigilator_port) {
  return boost::lexical_cast<std::string>(process_index) + kSeparator +
         boost::lexical_cast<std::string>(invigilator_port);
}

bool ParseVmidParameter(const std::string& invigilator_identifier,
                        ProcessIndex& process_index,
                        Port& invigilator_port) {
  auto do_fail([&]()->bool {
    process_index = invigilator_port = 0;
    return false;
  });

  size_t separator_position(invigilator_identifier.find(kSeparator));
  if (separator_position == std::string::npos) {
    LOG(kError) << "invigilator_identifier " << invigilator_identifier << " has wrong format";
    return do_fail();
  }
  try {
    process_index =
        boost::lexical_cast<ProcessIndex>(invigilator_identifier.substr(0, separator_position));
    invigilator_port =
        boost::lexical_cast<Port>(invigilator_identifier.substr(separator_position + 1));
  }
  catch(const boost::bad_lexical_cast& exception) {
    LOG(kError) << "invigilator_identifier " << invigilator_identifier
                << " has wrong format: " << exception.what();
    return do_fail();
  }

  if (process_index == 0) {
    LOG(kError) << "Invalid process index of 0";
    return do_fail();
  }

  if (invigilator_port < Invigilator::kMinPort() ||
      invigilator_port > Invigilator::kMaxPort()) {
    LOG(kError) << "Invalid Vaults Manager port " << invigilator_port;
    return do_fail();
  }

  return true;
}

uint16_t GetRandomPort() {
  static std::set<uint16_t> already_used_ports;
  bool unique(false);
  uint16_t port(0);
  uint16_t failed_attempts(0);
  do {
    port = (RandomUint32() % 48126) + 1025;
    unique = (already_used_ports.insert(port)).second;
  } while (!unique && failed_attempts++ < 1000);
  if (failed_attempts > 1000)
    LOG(kError) << "Unable to generate unique ports";
  return port;
}

bool GenerateFakeBootstrapFile(const int& number_of_entries) {
  protobuf::BootstrapEndpoints eps;
  for (int i(0); i < number_of_entries; ++i) {
    eps.add_bootstrap_endpoint_ip("127.0.0.1");
    eps.add_bootstrap_endpoint_port(5483);
  }
  return WriteFile(boost::filesystem::path(".") / "fake_bootstrap.dat", eps.SerializeAsString());
}

}  // namespace detail

}  //  namespace process_management

}  //  namespace priv

}  //  namespace maidsafe
