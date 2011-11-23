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

#include "maidsafe/private/chunk_action_authority.h"

#include "maidsafe/common/chunk_store.h"

#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"


namespace maidsafe {

namespace priv {

template <class ValidationType, class VersionType>
ChunkActionAuthority<ValidationType, VersionType>::ChunkActionAuthority()
    : ChunkValidation(),
      get_data_signal_(new GetDataSignalPtr::element_type) {}

template <class ValidationType, class VersionType>
ChunkActionAuthority<ValidationType, VersionType>::~ChunkActionAuthority() {}

template <class ValidationType, class VersionType>
std::shared_ptr<bs2::signal<void(const std::string&)>>
    ChunkActionAuthority<ValidationType, VersionType>::get_data_signal() {
  return get_data_signal_;
}

//int ChunkActionAuthority::ProcessData(const OperationType &op_type,
//                                      const std::string &name,
//                                      const std::string &data,
//                                      const asymm::PublicKey &public_key,
//                                      std::shared_ptr<ChunkStore> chunk_store) {
//  if (op_type == ChunkActionAuthority::kHas) {
//    if (chunk_store->Has(name))
//      return kKeyNotUnique;
//    else
//      return kKeyUnique;
//  }
//
//  DataWrapper data_wrapper;
//  if (op_type != ChunkActionAuthority::kGet) {
//    if (!data_wrapper.ParseFromString(data)) {
//      DLOG(WARNING) << "Failed to parse data. Could be chunk.";
//      return kParseFailure;
//    }
//  }
//
//  switch (data_wrapper.data_type()) {
//    case DataWrapper::kHashableSigned:
//        return ProcessSignedData(op_type, name, data_wrapper, public_key, true,
//                                 chunk_store);
//    case DataWrapper::kNonHashableSigned:
//        return ProcessSignedData(op_type, name, data_wrapper, public_key, false,
//                                 chunk_store);
//    default: return kUnknownFailure;
//  }
//}
//
//int ChunkActionAuthority::ProcessSignedData(
//    const OperationType &op_type,
//    const std::string &name,
//    const DataWrapper &data_wrapper,
//    const asymm::PublicKey &public_key,
//    const bool &hashable,
//    std::shared_ptr<ChunkStore> chunk_store) {
//  if (PreOperationChecks(op_type, name, data_wrapper, public_key, hashable) !=
//      kSuccess) {
//    DLOG(ERROR) << "ProcessSignedData - PreOperationChecks failure.";
//    return kPreOperationCheckFailure;
//  }
//
//  std::string current_data;
//  switch (op_type) {
//    case kStore: {
//      if (chunk_store->Has(name)) {
//        DLOG(ERROR) << "ProcessSignedData - Name of data exists. Use update.";
//        return kDuplicateNameFailure;
//      }
//      if (!chunk_store->Store(name, data_wrapper.SerializeAsString())) {
//        DLOG(ERROR) << "ProcessSignedData - ChunkStore Store failure.";
//        return kStoreFailure;
//      }
//      break;
//    }
//    case kDelete: {
//      if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
//          kSuccess) {
//        DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
//        return kVerifyDataFailure;
//      }
//
//      if (!chunk_store->Delete(name)) {
//        DLOG(ERROR) << "ProcessSignedData - Error deleting packet";
//        return kDeleteFailure;
//      }
//
//      break;
//    }
//    case kUpdate: {
//      if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
//          kSuccess) {
//        DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
//        return kVerifyDataFailure;
//      }
//      if (!chunk_store->Modify(name, data_wrapper.SerializeAsString())) {
//        DLOG(ERROR) << "ProcessSignedData - Error Modifying packet";
//        return kModifyFailure;
//      }
//      break;
//    }
//    case kGet: {
//      if (VerifyCurrentData(name, public_key, chunk_store, &current_data) !=
//          kSuccess) {
//        DLOG(ERROR) << "ProcessSignedData - VerifyCurrentData failure.";
//        return kVerifyDataFailure;
//      }
//
//      (*get_data_signal_)(current_data);
//      break;
//    }
//    case kHas: DLOG(INFO) << "At this moment, code should not reach here.";
//  }
//
//  return kSuccess;
//}
//
//int ChunkActionAuthority::PreOperationChecks(const OperationType &op_type,
//                                             const std::string &name,
//                                             const DataWrapper &data_wrapper,
//                                             const asymm::PublicKey &public_key,
//                                             const bool &hashable) {
//  if (op_type == kGet)
//    return kSuccess;
//
//  if (!data_wrapper.has_signed_data()) {
//    DLOG(ERROR) << "ProcessSignedData - No signed data passed";
//    return kMissingSignedData;
//  }
//
//  if (hashable && op_type == kUpdate) {
//    DLOG(ERROR) << "ProcessSignedData - No update of hashable data allowed";
//    return kInvalidUpdate;
//  }
//
//
//  if (!crypto::AsymCheckSig(data_wrapper.signed_data().data(),
//                            data_wrapper.signed_data().signature(),
//                            public_key)) {
//    DLOG(ERROR) << "ProcessSignedData - Signature verification failed";
//    return kSignatureVerificationFailure;
//  }
//
//  if (hashable &&
//      crypto::Hash<crypto::SHA512>(data_wrapper.signed_data().data() +
//                                   data_wrapper.signed_data().signature()) !=
//      name) {
//    DLOG(ERROR) << "ProcessSignedData - Marked hashable, doesn't hash";
//    return kNotHashable;
//  }
//
//  return kSuccess;
//}
//
//int ChunkActionAuthority::VerifyCurrentData(
//    const std::string &name,
//    const asymm::PublicKey &public_key,
//    std::shared_ptr<ChunkStore> chunk_store,
//    std::string *current_data) {
//  *current_data = chunk_store->Get(name);
//  if (current_data->empty()) {
//    DLOG(ERROR) << "VerifyCurrentData - Failure to get data";
//    return kVerifyDataFailure;
//  }
//
//  DataWrapper dw;
//  if (!dw.ParseFromString(*current_data)) {
//    DLOG(ERROR) << "VerifyCurrentData - Error parsing packet";
//    return kParseFailure;
//  }
//
//  if (!public_key.empty() &&
//      dw.has_signed_data() &&
//      !crypto::AsymCheckSig(dw.signed_data().data(),
//                            dw.signed_data().signature(),
//                            public_key)) {
//    DLOG(ERROR) << "VerifyCurrentData - Not owner of packet";
//    return kNotOwner;
//  }
//
//  *current_data = dw.signed_data().SerializeAsString();
//
//  return kSuccess;
//}

}  // namespace priv

}  // namespace maidsafe

