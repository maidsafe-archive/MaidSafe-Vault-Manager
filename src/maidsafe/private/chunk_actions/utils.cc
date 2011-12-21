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

#include "maidsafe/private/chunk_actions/utils.h"

#include "maidsafe/common/chunk_store.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"
#include "maidsafe/private/chunk_actions/chunk_pb.h"
#include "maidsafe/private/chunk_actions/default_rules.h"


namespace maidsafe {

namespace priv {

namespace chunk_actions {

//int ProcessSignedData(const ChunkActionAuthority::OperationType &op_type,
//                      const std::string &name,
//                      const std::string &data,
//                      const asymm::PublicKey &public_key,
//                      const bool &hashable,
//                      std::shared_ptr<ChunkStore> chunk_store,
//                      std::string *new_content) {
//  if (PreOperationChecks(op_type, name, data, public_key, hashable) !=
//      kSuccess) {
//    DLOG(ERROR) << "PreOperationChecks failure.";
//    return kPreOperationCheckFailure;
//  }
//
//  std::string existing_data;
//  if (op_type == ChunkActionAuthority::kDelete ||
//      op_type == ChunkActionAuthority::kModify ||
//      op_type == ChunkActionAuthority::kGet) {
//    if (VerifyCurrentData(name, public_key, chunk_store, &existing_data) !=
//        kSuccess) {
//      DLOG(ERROR) << "VerifyCurrentData failure.";
//      return kVerifyDataFailure;
//    }
//  }
//
//  switch (op_type) {
//    case ChunkActionAuthority::kStore:
//      if (chunk_store->Has(name)) {
//        DLOG(ERROR) << "Name of data exists. Use modify.";
//        return kDuplicateNameFailure;
//      }
//      if (!chunk_store->Store(name, data)) {
//        DLOG(ERROR) << "ChunkStore Store failure.";
//        return kStoreFailure;
//      }
//      break;
//    case ChunkActionAuthority::kDelete:
//      if (!chunk_store->Delete(name)) {
//        DLOG(ERROR) << "ChunkStore Delete failure.";
//        return kDeleteFailure;
//      }
//      break;
//    case ChunkActionAuthority::kModify:
//      if (!chunk_store->Modify(name, data)) {
//        DLOG(ERROR) << "ChunkStore Modify failure.";
//        return kModifyFailure;
//      }
//      break;
//    case ChunkActionAuthority::kGet:
//      break;
//    case ChunkActionAuthority::kHas:
//    default:
//      DLOG(INFO) << "At this moment, code should not reach here.";
//      return kGeneralError;
//  }
//
//  return kSuccess;
//}
//
//int PreOperationChecks(const ChunkActionAuthority::OperationType &op_type,
//                       const std::string &name,
//                       const std::string &data,
//                       const asymm::PublicKey &public_key,
//                       const bool &hashable) {
//  if (op_type == ChunkActionAuthority::kGet)
//    return kSuccess;
//
//  GenericPacket generic_packet;
//  try {
//    if (!generic_packet.ParseFromString(data)) {
//      DLOG(ERROR) << "Data doesn't parse as a GenericPacket";
//      return kInvalidSignedData;
//    }
//  }
//  catch(const std::exception &e) {
//    DLOG(ERROR) << "Data doesn't parse as a GenericPacket: " << e.what();
//    return kInvalidSignedData;
//  }
//
//  if (hashable) {
//    if (op_type == ChunkActionAuthority::kModify) {
//      DLOG(ERROR) << "No modify of hashable data allowed";
//      return kInvalidModify;
//    }
//    if (crypto::Hash<crypto::SHA512>(
//            generic_packet.data() + generic_packet.signature()) != name) {
//      DLOG(ERROR) << "Marked hashable, doesn't hash";
//      return kNotHashable;
//    }
//  }
//
//  if (asymm::CheckSignature(generic_packet.data(), generic_packet.signature(),
//                            public_key) != kSuccess) {
//    DLOG(ERROR) << "Signature verification failed";
//    return kSignatureVerificationFailure;
//  }
//
//  return kSuccess;
//}

//int VerifyCurrentData(const std::string &name,
//                      const asymm::PublicKey &public_key,
//                      std::shared_ptr<ChunkStore> chunk_store,
//                      std::string *existing_data) {
//  *existing_data = chunk_store->Get(name);
//  if (existing_data->empty()) {
//    DLOG(ERROR) << "VerifyCurrentData - Failure to get data";
//    return kVerifyDataFailure;
//  }
//
//  GenericPacket generic_packet;
//  try {
//    if (!generic_packet.ParseFromString(*existing_data)) {
//      DLOG(ERROR) << "Data doesn't parse as a GenericPacket";
//      return kInvalidSignedData;
//    }
//  }
//  catch(const std::exception &e) {
//    DLOG(ERROR) << "Data doesn't parse as a GenericPacket: " << e.what();
//    return kInvalidSignedData;
//  }
//
//  if (asymm::ValidateKey(public_key) &&
//      asymm::CheckSignature(generic_packet.data(),
//                            generic_packet.signature(),
//                            public_key) != kSuccess) {
//    DLOG(ERROR) << "VerifyCurrentData - Not owner of packet";
//    return kNotOwner;
//  }
//
//  return kSuccess;
//}

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

