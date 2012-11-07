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

#ifndef MAIDSAFE_PRIVATE_DATA_TYPES_NETWORK_ACTORS_H_
#define MAIDSAFE_PRIVATE_DATA_TYPES_NETWORK_ACTORS_H_

#include "maidsafe/common/types.h"
#include "maidsafe/private/data_types/data_manager.h"
#include "maidsafe/common/types.h"
#include "maidsafe/private/utils/fob.h"
#include "maidsafe/private/data_types/store_policies.h"
#include "maidsafe/private/data_types/get_policies.h"
#include "maidsafe/private/data_types/delete_policies.h"
#include "maidsafe/private/data_types/edit_policies.h"
#include "maidsafe/private/data_types/amend_policies.h"
// These are Actors in the maidsafe manner not actor based design (concurrency)
// Host class
template <typename StoragePolicy,
          typename StorePolicy,
          typename GetPolicy,
          typename DeletePolicy,
          typename EditPolicy,
          typename AppendPolicy>
class Actor : private StoragePolicy,
                    private StorePolicy,
                    private GetPolicy,
                    private DeletePolicy,
                    private EditPolicy,
                    private AppendPolicy {
 public:
  Actor(Routing routing) :
  //             chunk_store_dir_(chunk_store),
               routing_(routing),
  //             message_handler_() {}

  static bool Store(NonEmptyString key, NonEmptyString value, Signature Signature, Identity id) {
    return StoragePolicy::Process(StorePolicy::Store(NonEmptyString key, NonEmptyString value));
  }
  static GetPolicy::value Get(NonEmptyString key) {
    return StoragePolicy::Process(GetPolicy::Get(key));
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

// Actors

typedef Actor<StoreIfPayed, Get, template<DeleteIfOwner, DeleteIfTold>,
              template<EditByOwner, EditIfPayed>,AppendIfAllowed>
                                                                      ChunkHolder;
typedef Actor<StoreAll, Get, DeleteIfOwner, EditIfOwner, NoAppend>
                                                                      ChunkInfoHolder;

typedef Actor<StoreAll, Get, DeleteIfOwner, NoEdit, AppendIfAllowed>
                                                                      AccountHolder;

typedef Actor<StoreAndPay, Get, Delete, Edit, Append>
                                                                      Client;

#endif  // MAIDSAFE_PRIVATE_DATA_TYPES_NETWORK_ACTORS_H_

