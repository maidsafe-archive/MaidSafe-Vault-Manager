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

#ifndef MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_TYPE_H_
#define MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_TYPE_H_


namespace maidsafe {

namespace priv {

enum class ChunkType : char {
  kDefault = 0,
  kAppendableByAll = 1,
  kModifiableByOwner = 2,
  kSignaturePacket = 3,
  kUnknown = 0x80
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_TYPE_H_
