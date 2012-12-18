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

#ifndef MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_RETURN_CODES_H_
#define MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_RETURN_CODES_H_

namespace maidsafe {

enum ReturnCode {
  kSuccess = 0,

  // Download Manager
  kUninitialised = -250001,
  kManifestFailure = -250002,
  kDownloadFailure = -250003,
  kNoVersionChange = -250004,
  kLocalFailure = -250005,

  // Transport
  kAlreadyStarted = -350001,
  kInvalidAddress = -350002,
  kSetOptionFailure = -350003,
  kBindError = -350004,
  kListenError = -350005,
  kMessageSizeTooLarge = -350006,
  kReceiveFailure = -350007,
  kReceiveTimeout = -350008,
  kSendFailure = -350009,
  kSendTimeout = -350010,
  kConnectFailure = -350011
};

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_LIFESTUFF_MANAGER_RETURN_CODES_H_
