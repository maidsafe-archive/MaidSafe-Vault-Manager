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

#ifndef MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_ID_H_
#define MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_ID_H_

#include <string>

#include "maidsafe/common/bounded_string.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/node_id.h"

#include "maidsafe/private/chunk_actions/chunk_type.h"


namespace maidsafe {

namespace priv {

typedef detail::BoundedString<NodeId::kSize, NodeId::kSize + 1> ChunkId;

inline ChunkId ApplyTypeToName(const NodeId& name, ChunkType chunk_type) {
  return ChunkId(chunk_type == ChunkType::kDefault ?
                 name.string() : name.string() + static_cast<char>(chunk_type));
}

inline NodeId RemoveTypeFromName(const ChunkId& name) {
  return NodeId(name.string().substr(0, NodeId::kSize));
}

inline ChunkType GetChunkType(const ChunkId& name) {
  if (name.string().size() == static_cast<size_t>(NodeId::kSize))
    return ChunkType::kDefault;

  ChunkType chunk_type(static_cast<ChunkType>(*name.string().rbegin()));
  switch (chunk_type) {
    case ChunkType::kAppendableByAll:
    case ChunkType::kModifiableByOwner:
    case ChunkType::kSignaturePacket:
      return chunk_type;
    default:
      LOG(kWarning) << "Unknown data type " << static_cast<int>(chunk_type);
      return ChunkType::kUnknown;
  }
}

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_ID_H_
