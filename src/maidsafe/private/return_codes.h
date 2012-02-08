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

#if MAIDSAFE_PRIVATE_VERSION != 200
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif

namespace maidsafe {

namespace priv {

enum ReturnCode {
  kSuccess = 0,
  kGeneralError = -100001,
  kUnknownFailure = -150002,
  kNullParameter = -150003,
  kKeyNotUnique = -150004,
  kKeyUnique = -150005,
  kParseFailure = -150006,
  kPreOperationCheckFailure = -150007,
  kDuplicateNameFailure = -150008,
  kVerifyDataFailure = -150009,
  kStoreFailure = -150010,
  kDeleteFailure = -150011,
  kModifyFailure = -150012,
  kInvalidSignedData = -150013,
  kInvalidModify = -150014,
  kSignatureVerificationFailure = -150015,
  kNotHashable = -150016,
  kNotOwner = -150017,
  kInvalidChunkType = -150018,
  kFailedToFindChunk = -150019,
  kInvalidPublicKey = -150020,
  kAppendDisallowed = -150021,
  kHashFailure = -150022,
  kDifferentVersion = -150023
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_RETURN_CODES_H_
