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

#ifndef MAIDSAFE_PRIVATE_CONFIG_H_
#define MAIDSAFE_PRIVATE_CONFIG_H_

#include <functional>
#include <memory>
#include <string>

#include "maidsafe/common/rsa.h"

#include "maidsafe/private/version.h"

#if MAIDSAFE_PRIVATE_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif


namespace maidsafe {

namespace priv {

class ChunkStore;

enum OperationType { kStore, kDelete, kUpdate, kGet, kHas };

extern const unsigned char kUnknownDataType;

typedef std::shared_ptr<ChunkStore> ChunkStorePtr;
typedef std::function<int(const OperationType&,
                          const std::string&,  // name
                          const std::string&,  // data
                          const asymm::PublicKey&,
                          ChunkStorePtr)> ProcessDataFunctor;


}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CONFIG_H_
