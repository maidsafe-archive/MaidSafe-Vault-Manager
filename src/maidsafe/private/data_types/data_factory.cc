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
#include "maidsafe/private/data_types/data_types.h"

#include <memory>
#include <string>
#include <map>

#include "boost/filesystem/path.hpp"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/data_types/data_factory.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

namespace {
  DataType* CreateImmutableData(DataTypes::kDefault) {
    return new ImmutableData;
  }

}  // anonymous namespace


DataFactory::DataTypes*  CreateDataType(DataTypes data_type) {
  CreateDataType::const::iterator i = callbacks_.find(data_type);
  if (i == callbacks_.end())
   ThrowError(CommonErrors::invalid_data_type);
  return (i->second);
}

bool DataFactory::RegisterDataType(DataTypes data_type, CreateDataTypeCallback create_callback) {
  return callbacks_.insert(CallbackMap::value_type(data_type, create_callback));
}

bool DataFactory::UnregisterDataType(DataTypes data_type) {
  return callbacks_.erase(data_type) == 1;
}







}  // namespace priv

}  // namespace maidsafe

