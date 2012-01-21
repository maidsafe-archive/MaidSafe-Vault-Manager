/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file licence.txt found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_PRIVATE_RETURN_CODES_H_
#define MAIDSAFE_PRIVATE_RETURN_CODES_H_

#include "maidsafe/private/version.h"

#if MAIDSAFE_PRIVATE_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif

namespace maidsafe {

namespace priv {

enum ReturnCode {
  kSuccess = 0,
  kGeneralError = -100001,
  kUnknownFailure = -150001,
  kNullParameter = -150002,
  kKeyNotUnique = -150002,
  kKeyUnique = -150003,
  kParseFailure = -150004,
  kPreOperationCheckFailure = -150005,
  kDuplicateNameFailure = -150006,
  kVerifyDataFailure = -150007,
  kStoreFailure = -150008,
  kDeleteFailure = -150009,
  kModifyFailure = -150010,
  kInvalidSignedData = -150011,
  kInvalidModify = -150012,
  kSignatureVerificationFailure = -150013,
  kNotHashable = -150014,
  kNotOwner = -150015,
  kInvalidChunkType = -150016,
  kFailedToFindChunk = -150017,
  kInvalidPublicKey = -150018,
  kAppendDisallowed = -150019
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_RETURN_CODES_H_
