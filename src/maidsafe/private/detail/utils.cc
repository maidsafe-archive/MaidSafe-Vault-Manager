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

#include "maidsafe/private/detail/utils.h"

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/chunk_action_authority.h"

#include "maidsafe/private/chunk_messages_pb.h"
#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"
#include "maidsafe/private/detail/hashable_signed_rules.h"


namespace maidsafe {

namespace priv {

unsigned char GetDataType(const std::string &name) {
  if (name.size() == crypto::SHA512::DIGESTSIZE)
    return kHashableSignedData;

  if (name.size() == crypto::SHA512::DIGESTSIZE + 1)
    return name.front();

  DLOG(WARNING) << "Unknown data type " << static_cast<int>(name.front());
  return kUnknownData;
}


namespace detail {

int ProcessSignedData(const int &op_type,
                      const std::string &name,
                      const std::string &data,
                      const asymm::PublicKey &public_key,
                      const bool &hashable,
                      std::shared_ptr<ChunkStore> chunk_store,
                      std::string *new_content) {
  if (PreOperationChecks(op_type, name, data, public_key, hashable) !=
      kSuccess) {
    DLOG(ERROR) << "PreOperationChecks failure.";
    return kPreOperationCheckFailure;
  }

  std::string current_data;
  switch (op_type) {
    case ChunkActionAuthority::kStore:
      if (chunk_store->Has(name)) {
        DLOG(ERROR) << "Name of data exists. Use update.";
        return kDuplicateNameFailure;
      }
      break;
    case ChunkActionAuthority::kDelete:
    case ChunkActionAuthority::kUpdate:
    case ChunkActionAuthority::kGet:
      if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
          kSuccess) {
        DLOG(ERROR) << "VerifyCurrentData failure.";
        return kVerifyDataFailure;
      }
      break;
    case ChunkActionAuthority::kHas:
    default:
      DLOG(INFO) << "At this moment, code should not reach here.";
      return kGeneralError;
  }

  return kSuccess;
}

int PreOperationChecks(const int &op_type,
                       const std::string &name,
                       const std::string &data,
                       const asymm::PublicKey &public_key,
                       const bool &hashable) {
  if (op_type == ChunkActionAuthority::kGet)
    return kSuccess;

  GenericPacket generic_packet;
  try {
    if (!generic_packet.ParseFromString(data)) {
      DLOG(ERROR) << "Data doesn't parse as a GenericPacket";
      return kInvalidSignedData;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Data doesn't parse as a GenericPacket: " << e.what();
    return kInvalidSignedData;
  }

  if (hashable) {
    if (op_type == ChunkActionAuthority::kUpdate) {
      DLOG(ERROR) << "No update of hashable data allowed";
      return kInvalidUpdate;
    }
    if (crypto::Hash<crypto::SHA512>(
            generic_packet.data() + generic_packet.signature()) != name) {
      DLOG(ERROR) << "Marked hashable, doesn't hash";
      return kNotHashable;
    }
  }

  if (asymm::CheckSignature(generic_packet.data(), generic_packet.signature(),
                            public_key) != kSuccess) {
    DLOG(ERROR) << "Signature verification failed";
    return kSignatureVerificationFailure;
  }

  return kSuccess;
}

int VerifyCurrentData(const std::string &name,
                      const asymm::PublicKey &public_key,
                      std::shared_ptr<ChunkStore> chunk_store,
                      std::string *current_data) {
  *current_data = chunk_store->Get(name);
  if (current_data->empty()) {
    DLOG(ERROR) << "VerifyCurrentData - Failure to get data";
    return kVerifyDataFailure;
  }

  GenericPacket generic_packet;
  try {
    if (!generic_packet.ParseFromString(*current_data)) {
      DLOG(ERROR) << "Data doesn't parse as a GenericPacket";
      return kInvalidSignedData;
    }
  }
  catch(const std::exception &e) {
    DLOG(ERROR) << "Data doesn't parse as a GenericPacket: " << e.what();
    return kInvalidSignedData;
  }

  if (asymm::ValidateKey(public_key) &&
      asymm::CheckSignature(generic_packet.data(),
                            generic_packet.signature(),
                            public_key) != kSuccess) {
    DLOG(ERROR) << "VerifyCurrentData - Not owner of packet";
    return kNotOwner;
  }

  return kSuccess;
}

}  // namespace detail

}  // namespace priv

}  // namespace maidsafe

