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

#include "maidsafe/private/detail/msid_rules.h"

#include "maidsafe/common/chunk_action_authority.h"
#include "maidsafe/common/chunk_store.h"

#include "maidsafe/private/chunk_messages_pb.h"
#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"


namespace maidsafe {

namespace priv {

namespace detail {

template<>
int ProcessData<kMsidData>(const int &op_type,
                           const std::string &name,
                           const std::string &content,
                           const asymm::PublicKey &public_key,
                           std::shared_ptr<ChunkStore> chunk_store,
                           std::string *new_content) {
  std::string current_data(chunk_store->Get(name));
  bool already_exists(true);
  if (current_data.empty()) {
    DLOG(INFO) << "No such MSID";
    already_exists = false;
  }

  if (already_exists) {
    DataWrapper data_wrapper;
    if (!data_wrapper.ParseFromString(current_data)) {
      DLOG(ERROR) << "current MSID corrupted";
      return kParseFailure;
    }

    MSID current_msid;
    if (!current_msid.ParseFromString(
            data_wrapper.signed_data().data())) {
      DLOG(ERROR) << "current MSID corrupted";
      return kParseFailure;
    }

    if (asymm::CheckSignature(current_msid.public_key(),
                              current_msid.signature(),
                              public_key) != 0) {
      DLOG(INFO) << "Not owner, can only store MCID or get keys from MSID";
      if (op_type == kStore) {
        if (current_msid.accepts_new_contacts()) {
          current_msid.add_encrypted_mcid(data.signed_data().data());
          data_wrapper.mutable_signed_data()->set_data(
              current_msid.SerializeAsString());
          if (!chunk_store->Modify(name,
                                   data_wrapper.SerializeAsString())) {
            DLOG(ERROR) << "Failed to add MCID";
            return kModifyFailure;
          }
        } else {
          DLOG(INFO) << "Not accepting MCIDs";
          return kWontAcceptContact;
        }
      } else if (op_type == kGet) {
        GenericPacket gp;
        gp.set_data(current_msid.public_key());
        gp.set_signature(current_msid.signature());
        gp.set_type(kMsid);
        (*get_string_signal_)(gp.SerializeAsString());
      } else {
        DLOG(ERROR) << "Forbidden operation";
        return kUnknownFailure;
      }
    } else {
      switch (op_type) {
        case kGet:
          if (current_msid.encrypted_mcid_size() > 0) {
            std::vector<std::string> mcids;
            for (int n(0); n != current_msid.encrypted_mcid_size(); ++n)
              mcids.push_back(current_msid.encrypted_mcid(n));
            current_msid.clear_encrypted_mcid();
            data_wrapper.mutable_signed_data()->set_data(
                current_msid.SerializeAsString());
            if (!chunk_store->Modify(
                    name,
                    data_wrapper.SerializeAsString())) {
              DLOG(ERROR) << "Failed to modify after geting MCIDs";
              return kModifyFailure;
            }
            (*get_vector_signal_)(mcids);
          }
          break;
        case kUpdate:
          /***
            * If owner, change the allowance of storage.
            * Other ops in the future?
            ***/
            break;
        case kDelete:
          // Delete the whole thing
          if (!chunk_store->Delete(name)) {
            DLOG(ERROR) << "Failure to delete value";
            return kDeleteFailure;
          }
          /************** or all messages
          MSID mmid;
          msid.Parse(current_data);
          msid.clear_encrypted_mcid();
          ******************************/
        default: return kUnknownFailure;
      }
    }
  } else {
    // Storing the whole thing
    MSID wrapper_msid;
    if (!wrapper_msid.ParseFromString(data.signed_data().data())) {
      DLOG(ERROR) << "Data doesn't parse";
      return kStoreFailure;
    }

    if (asymm::CheckSignature(wrapper_msid.public_key(),
                              wrapper_msid.signature(),
                              public_key) != 0) {
      DLOG(ERROR) << "Failed validation of data";
      return kStoreFailure;
    }

    std::string a(data.SerializeAsString());
    if (!chunk_store->Store(name, a)) {
      DLOG(ERROR) << "Failed committing to chunk store";
      return kStoreFailure;
    }
  }

  return kSuccess;
}

template<>
int ProcessData<kMsidData>(const int &op_type,
                           const std::string &name,
                           const fs::path &path,
                           const asymm::PublicKey &public_key,
                           std::shared_ptr<ChunkStore> chunk_store,
                           std::string *new_content) {
}

}  // namespace detail

}  // namespace priv

}  // namespace maidsafe
