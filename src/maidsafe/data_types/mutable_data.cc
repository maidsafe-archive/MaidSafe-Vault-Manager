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
#include "maidsafe/data_types/mutable_data.h"

#include "maidsafe/common/types.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"

#include "maidsafe/data_types/data_pb.h"

namespace maidsafe {

MutableData::MutableData(const ChunkId name,
                         const NonEmptyString content,
                         const rsa::Signature signature) {}

MutableData::MutableData(const NonEmptyString serialised_data) {}

MutableData::NonEmptyString Serialise() {}

MutableData::Identity name() {}

MutableData::NonEmptyString version() {}

}  // namespace maidsafe

