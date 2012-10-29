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

#include "maidsfe/private/utils/fob.h"

// Policy classes
// STORE
template <typename T>
class StoreAndPay {
 protected:  // not exposing rich interface (public inheritance)
  static bool StoreAndPay(T) {
  // implementation
  }
};

template <typename T>
class StoreAll {
 protected:
  static bool StoreAll(T) {
  // implementation
  }
};

// DELETE
template <typename T>
class DeleteByRemovingReference {
 protected:
  static bool Delete(T) {
    // remove the reference 
    //if (no more references)
    DefaultDeletePolicy(T);
  }
};

template <typename T>
class DeleteIfOwner {
 protected:
  static bool Delete(T) {
    // move to cache
};

template <typename T>
class ZeroOutIfOwner {
 protected:
  static bool Delete(T) {
    // move to cache
};

// GET
template <typename T>
class GetDataElementsOnly {
 protected:
  static T Get() {
  }
};

template <typename T>
class GetAllElements {
 protected:
  static T Get() {
  }
};

// EDIT
template <typename T>
class EditIfOwner {
};

template <typename T>
class NoEdit {
 protected:
  static bool Edit { return true; }
};

// APPEND
template <typename T>
class NoAppend {
 protected:
  static bool Append(T, Authority auth) { return true; }
};

template <typename T>
class AppendIfAllowed {
 protected:
  static bool Append(T, Authority auth)  {
  // implementation 
 }
};


// AUTHORITY
template <typename T>
class CheckSignature {

};

// CACHE
template <typename T>
class MemoryCache {

};

template <typename T>
class DiskTermCache {

};

template <typename T>
class LongTermCache {

};

template <typename T>
class NoCache{
 public:
  NoCache();
  static bool Cache(T) { return true; }
};

// Host class

template <typename StorePolicy,
          typename GetPolicy,
          typename DeletePolicy,
          typename EditPolicy,
          typename AppendPolicy>
class DataHandler : private StorePolicy,
                    private GetPolicy,
                    private DeletePolicy,
                    private EditPolicy,
                    private AppendPolicy {
 public:
  DataHandler(std::fstream chunk_store_dir,Routing routing);

 private:
  std::fstream chunk_store_dir_;
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

#endif  // MAIDSAFE_PRIVATE_DATA_MANAGER_H_

