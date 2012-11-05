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

#ifndef MAIDSAFE_PRIVATE_DATA_MANAGER_H_
#define MAIDSAFE_PRIVATE_DATA_MANAGER_H_

#include "maidsafe/common/types.h"
#include "maidsafe/private/utils/fob.h"

// Policy classes
// STORE
class StoreToNetwork {
 protected:  // not exposing rich interface (public inheritance)
template <typename T>
  static bool Store(T) {
  // implementation
  }
};

class StoreToDisk {
 protected:
   template <typename T>
  static bool Store(const ChunkId& name,
                    const NonEmptyString& content,
                    const asymm::PublicKey& public_key,
                    std::shared_ptr<chunk_store::ChunkStore> chunk_store) {
  std::string existing_content(chunk_store->Get(name));
  if (existing_content.empty()) {
    // New chunk on network - check data hashes to name
    if (crypto::Hash<crypto::SHA512>(content).string() != RemoveTypeFromName(name).string()) {
      LOG(kError) << "Failed to store " << Base32Substr(name)
                  << ": default chunk type should be hashable";
      return kNotHashable;
    }
  } else {
    // Pre-existing chunk - ensure data is identical
    if (existing_content != content.string()) {
      LOG(kError) << "Failed to store " << Base32Substr(name)
                  << ": existing data doesn't match new data - can't store";
      return kInvalidSignedData;
    }
  }

  return kSuccess;
  // implementation
  }
};

// DELETE
class DeleteByRemovingReference {
 protected:
template <typename T>
  static bool Delete(T) {
    // remove the reference 
    //if (no more references)
    DefaultDeletePolicy(T);
  }
};

class DeleteIfOwner {
 protected:
template <typename T>
  static bool Delete(T) {
    // move to cache
};

class ZeroOutIfOwner {
 protected:
template <typename T>
  static bool Delete(T) {
    // move to cache
};

// GET
class GetDataElementsOnly {
 protected:
template <typename T>
  static T Get() {
  }
};

class GetAllElements {
 protected:
template <typename T>
  static T Get() {
  }
};

// EDIT
class EditIfOwner {
template <typename T>
};

class NoEdit {
 protected:
template <typename T>
  static bool Edit { return true; }
};

// APPEND
class NoAppend {
 protected:
template <typename T>
  static bool Append(T, Authority auth) { return true; }
};

class AppendIfAllowed {
 protected:
template <typename T>
  static bool Append(T, Authority auth)  {
  // implementation 
 }
};


// AUTHORITY
class CheckSignature {
template <typename T>

};

// CACHE
class MemoryCache {
template <typename T>

};

class DiskTermCache {
template <typename T>

};

class LongTermCache {
template <typename T>

};

class NoCache{
 public:
template <typename T>
  NoCache();
  static bool Cache(T) { return true; }
};


// Host class

template <typename StorePolicy,  // make / check payment
          typename GetPolicy,  // nodes may cache on receipt or get retrieves only some data etc.
          typename DeletePolicy,  // get / send refund
          typename EditPolicy,  // get / send refund
          typename AppendPolicy>  // allowed
class DataHandler : private StorePolicy,
                    private GetPolicy,
                    private DeletePolicy,
                    private EditPolicy,
                    private AppendPolicy {
 public:
  DataHandler(Routing routing) :
  //             chunk_store_dir_(chunk_store),
               routing_(routing),
  //             message_handler_() {}
  // Default, hash of content == name
  // DataHandler(const ChunkId name, const NonEmptyString content);
  // // Signature, (hash of content + sig == name) !! (content == 0 and signed)
  // DataHandler(const ChunkId name,
  //             const asymm::PublicKey content,
  //             const Signature signature,
  //             const asymm::PublicKey public_key);
  // // Edit by owner
  // DataHandler(const ChunkId name,
  //             const NonEmptyString content,
  //             const Signature signature,
  //             const asymm::PublicKey public_key);
  // // Appendable by all
  // DataHandler(const ChunkId name,
  //             const NonEmptyString content,
  //             const std::vector<asymm::PublicKey> allowed,
  //             const Signature signature,
  //             const asymm::PublicKey public_key);

  static bool Store(NonEmptyString key, NonEmptyString value, Signature Signature, Identity id) {
    return StorePolicy::Store(NonEmptyString key, NonEmptyString value);
  }
  static GetPolicy::value Get(NonEmptyString key) {
    return GetPolicy::Get(key);
  }
  static bool Delete(NonEmptyString key, Signature Signature, Identity id) {
    return DeletePolicy::Delete(key);
  }
  static bool Edit(NonEmptyString& key,
                   NonEmptyString& version,  // or old_content ??
                   NonEmptyString& new_content) {
    return EditPolicy::Edit(key, version, value);
  }
 private:
  Routing routing_;
  MessageHandler message_handler_;
};

// Data types

typedef DataHandler<StoreAndPay, GetDataElementOnly, DeleteByRemovingReference, NoEdit, NoAppend>
                                                                            ImmutableData;
typedef DataHandler<StoreAll, GetAllElements, DeleteIfOwner, EditIfOwner, NoAppend>
                                                                            MutableData;

typedef DataHandler<StoreAll, GetAllElements, DeleteIfOwner, NoEdit, AppendIfAllowed>
                                                                            AppendableData;

typedef DataHandler<StoreAll, GetAllElements, ZeroOutIfOwner, NoEdit, NoAppend>
                                                                            SignatureData;
//########################################################################################
typedef DatatHandler <> ClientDataHandler;
typedef DatatHandler <> VaultDataHandler;
typedef DatatHandler <> CIHDataHandler;

template <typename T>
std::string SerialiseDataType(T t) {

}

template <typename T>
T ParseDataType(std::string serialised_data) {

}

// this can all go in a cc file
// Default, hash of content == name
ImmutableData CreateDataType(const ChunkId name,const NonEmptyString content) {
  // .... do stuff to check
  // this probably a try catch block !!
  return ImmutableData(const ChunkId name,const NonEmptyString content);
}

// Signature, (hash of content + sig == name) !! (content == 0 and signed)
SignatureData CreateDataType(const ChunkId name,
                             const asymm::PublicKey content,
                             const Signature signature,
                             const asymm::PublicKey public_key);
// Edit by owner
MutableData signatureData CreateDataType(const ChunkId name,
                                         const NonEmptyString content,
                                         const Signature signature,
                                         const asymm::PublicKey public_key);
// Appendable by all
AppendableData CreateDataType(const ChunkId name,
                              const NonEmptyString content,
                              const std::vector<asymm::PublicKey> allowed,
                              const Signature signature,
                              const asymm::PublicKey public_key);


#endif  // MAIDSAFE_PRIVATE_DATA_MANAGER_H_

