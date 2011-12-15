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

#include "maidsafe/private/detail/hashable_signed_rules.h"

#include "maidsafe/common/chunk_action_authority.h"
#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"

#include "maidsafe/private/chunk_messages_pb.h"
#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"


namespace maidsafe {

namespace priv {

namespace detail {

template<>
int ProcessData<kHashableSignedData>(const int &op_type,
                                     const std::string &name,
                                     const std::string &content,
                                     const asymm::PublicKey &public_key,
                                     std::shared_ptr<ChunkStore> chunk_store,
                                     std::string *new_content) {
  if (op_type == ChunkActionAuthority::kUpdate) {
    DLOG(ERROR) << "No update of hashable data allowed";
    return kInvalidUpdate;
  }

  if (op_type != ChunkActionAuthority::kHas &&
      op_type != ChunkActionAuthority::kGet) {
    GenericPacket generic_packet;
    try {
      if (!generic_packet.ParseFromString(content)) {
        DLOG(ERROR) << "Data doesn't parse as a GenericPacket";
        return kInvalidSignedData;
      }
    }
    catch(const std::exception &e) {
      DLOG(ERROR) << "Data doesn't parse as a GenericPacket: " << e.what();
      return kInvalidSignedData;
    }

    if (crypto::Hash<crypto::SHA512>(
            generic_packet.data() + generic_packet.signature()) != name) {
      DLOG(ERROR) << "Marked hashable, doesn't hash";
      return kNotHashable;
    }

    if (asymm::CheckSignature(generic_packet.data(), generic_packet.signature(),
                              public_key) != kSuccess) {
      DLOG(ERROR) << "Signature verification failed";
      return kSignatureVerificationFailure;
    }
  }

  std::string current_data;
  switch (op_type) {
    case ChunkActionAuthority::kStore:
      if (chunk_store->Has(name)) {
        DLOG(ERROR) << "Name of data exists. Use update.";
        return kDuplicateNameFailure;
      }
      if (new_content)
        *new_content = content;
      break;
    case ChunkActionAuthority::kDelete:
      if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
          kSuccess) {
        DLOG(ERROR) << "VerifyCurrentData failure.";
        return kVerifyDataFailure;
      }
      break;
    case ChunkActionAuthority::kGet:
    case ChunkActionAuthority::kHas:
    default:
      break;
  }

  return kSuccess;
}

template<>
int ProcessData<kHashableSignedData>(const int &op_type,
                                     const std::string &name,
                                     const fs::path &path,
                                     const asymm::PublicKey &public_key,
                                     std::shared_ptr<ChunkStore> chunk_store,
                                     std::string *new_content) {

}

}  // namespace detail

}  // namespace priv

}  // namespace maidsafe
