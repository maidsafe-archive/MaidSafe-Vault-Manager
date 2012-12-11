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

#ifndef MAIDSAFE_PRIVATE_CLIENT_DATA_TYPES_H_
#define MAIDSAFE_PRIVATE_CLIENT_DATA_TYPES_H_

#include "maidsafe/common/types.h"
#include "maidsafe/private/data_types/data_manager.h"


// Data types

typedef DataHandler<StoreAndPay, GetDataElementOnly, DeleteByRemovingReference, NoEdit, NoAppend>
                                                                            ImmutableData;
typedef DataHandler<StoreAll, GetAllElements, DeleteIfOwner, EditIfOwner, NoAppend>
                                                                            MutableData;

typedef DataHandler<StoreAll, GetAllElements, DeleteIfOwner, NoEdit, AppendIfAllowed>
                                                                            AppendableData;

typedef DataHandler<StoreAll, GetAllElements, ZeroOutIfOwner, NoEdit, NoAppend>
                                                                            SignatureData;
#endif  // MAIDSAFE_PRIVATE_CLIENT_DATA_TYPES_H_

