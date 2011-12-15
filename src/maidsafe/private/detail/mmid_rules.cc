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

#include "maidsafe/private/detail/mmid_rules.h"

#include "maidsafe/common/chunk_action_authority.h"
#include "maidsafe/common/chunk_store.h"

#include "maidsafe/private/chunk_messages_pb.h"
#include "maidsafe/private/return_codes.h"
#include "maidsafe/private/log.h"


namespace maidsafe {

namespace priv {

namespace detail {

template<>
int ProcessData<kMmidData>(const int &op_type,
                           const std::string &name,
                           const std::string &content,
                           const asymm::PublicKey &public_key,
                           std::shared_ptr<ChunkStore> chunk_store,
                           std::string *new_content) {
  // Check existance
  std::string current_data(chunk_store->Get(name));
  bool already_exists(true);
  if (current_data.empty()) {
    DLOG(INFO) << "No such MMID";
    already_exists = false;
  }

  // Check ownership
    // not owner, store message, no checks
    // owner, get messages, delete, store initially
  if (already_exists) {
    DataWrapper data_wrapper;
    if (!data_wrapper.ParseFromString(current_data)) {
      DLOG(ERROR) << "current MMID - DataWrapper corrupted";
      return kParseFailure;
    }

    MMID current_mmid;
    if (!current_mmid.ParseFromString(
            data_wrapper.signed_data().data())) {
      DLOG(ERROR) << "current MMID corrupted";
      return kParseFailure;
    }

    if (asymm::CheckSignature(current_mmid.public_key(),
                              current_mmid.signature(),
                              public_key) != 0) {
      DLOG(INFO) << "Not owner, can only store Encrypted or get keys from MMID "
                 << Base32Substr(name);
      if (op_type == kStore) {
        if (!current_mmid.add_encrypted_message()->ParseFromString(
            data.signed_data().data())) {
          DLOG(ERROR) << "Failed to parse Encrypted";
          return kModifyFailure;
        }
        data_wrapper.mutable_signed_data()->set_data(
            current_mmid.SerializeAsString());
        if (!chunk_store->Modify(name,
                                 data_wrapper.SerializeAsString())) {
          DLOG(ERROR) << "Failed to add MCID";
          return kModifyFailure;
        }
      } else if (op_type == kGet) {
        GenericPacket gp;
        gp.set_data(current_mmid.public_key());
        gp.set_signature(current_mmid.signature());
        gp.set_type(kMmid);
        (*get_string_signal_)(gp.SerializeAsString());
      } else {
        DLOG(ERROR) << "Forbidden operation";
        return kUnknownFailure;
      }
    } else {
      switch (op_type) {
        case kGet:
//            (*get_string_signal_)(current_data);
          if (current_mmid.encrypted_message_size() > 0) {
            std::vector<std::string> mmids;
            for (int n(0); n != current_mmid.encrypted_message_size(); ++n)
              mmids.push_back(
                  current_mmid.encrypted_message(n).SerializeAsString());
            current_mmid.clear_encrypted_message();
            data_wrapper.mutable_signed_data()->set_data(
                current_mmid.SerializeAsString());
            if (!chunk_store->Modify(
                    name,
                    data_wrapper.SerializeAsString())) {
              DLOG(ERROR) << "Failed to modify after geting MCIDs";
              return kModifyFailure;
            }
            (*get_vector_signal_)(mmids);
          }
          break;
        case kDelete:
          // Delete the whole thing
          if (!chunk_store->Delete(name)) {
            DLOG(ERROR) << "Failure to delete value";
            return kDeleteFailure;
          }
          /************** or all messages
          MMID mmid;
          mmid.Parse(current_data);
          mmid.clear_encrypted_message();
          ******************************/
        default: return kUnknownFailure;
      }
    }
  } else {
    // Storing the whole thing
    MMID wrapper_msid;
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
    } else {
      DLOG(ERROR) << "Stored MMID: " << Base32Substr(name);
    }
  }

  return kSuccess;
}

template<>
int ProcessData<kMmidData>(const int &op_type,
                           const std::string &name,
                           const fs::path &path,
                           const asymm::PublicKey &public_key,
                           std::shared_ptr<ChunkStore> chunk_store,
                           std::string *new_content) {
}

}  // namespace detail

}  // namespace priv

}  // namespace maidsafe
