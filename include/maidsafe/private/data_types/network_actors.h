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

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/types.h"
#include "maidsafe/common/types.h"
#include "maidsafe/private/utils/fob.h"
#include "maidsafe/private/data_types/store_policies.h"
#include "maidsafe/private/data_types/get_policies.h"
#include "maidsafe/private/data_types/delete_policies.h"
#include "maidsafe/private/data_types/edit_policies.h"
#include "maidsafe/private/data_types/amend_policies.h"
#include "maidsafe/routing/routing_api.h"

namespace maidsafe {

template <typename DataType,
          template <class> class StoragePolicy, // network disk proxy
          template <class> class PaymentPolicy,  // pay|refund check issue
          template <class> class StorePolicy,
          template <class> class GetPolicy,
          template <class> class DeletePolicy,
          template <class> class EditPolicy,
          template <class> class AppendPolicy>
class DataHandler : private StorePolicy<typename PaymentPolicy<DataType>::payment_type>,
                    private GetPolicy<DataType>,
                    private DeletePolicy<typename PaymentPolicy<DataType>::payment_type>,
                    private EditPolicy<typename PaymentPolicy<DataType>::payment_type>,
                    private AppendPolicy<DataType> {
 public:
  DataHandler(routing::Routing network, boost::filesystem::path fs_path) :
               fs_path_(fs_path),
               network_(network) {}

  static bool Store(DataType data) {
    return StorePolicy::Store(data));
  }
  static bool Get(DataType data) {
    return GetPolicy::Get(data);
  }
  static bool Delete(DataType data) {
    return DeletePolicy::Delete(data);
  }
  static bool Edit(DataType data,
                   NonEmptyString& version,  // or old_content ??
                   NonEmptyString& new_content) {
    return EditPolicy::Edit(key, version, value);
  }
 private:
  boost::filesystem::path fs_path_;
  routing::Routing network_;
  DataType data_;
};

// DataHandlers

typedef DataHandler<StoreIfPayed, Get, template<DeleteIfOwner, DeleteIfTold>,
              template<EditByOwner, EditIfPayed>,AppendIfAllowed>
                                                                      DataHolder;
typedef DataHandler<StoreAndPay, Get, DeleteAndRefund, EditIfOwner, NoAppend>
                                                                      DataManager;

typedef DataHandler<StoreIssuePayment, Get, DeleteGetRefund, EditAndBalance, AppendNoPay>
                                                                      AccountManager;

typedef DataHandler<StoreAndPay, Get, Delete, Edit, Append>
                                                                      ClientDataHandler;

}  // namespace maidsafe
#endif  // MAIDSAFE_PRIVATE_DATA_TYPES_NETWORK_ACTORS_H_

