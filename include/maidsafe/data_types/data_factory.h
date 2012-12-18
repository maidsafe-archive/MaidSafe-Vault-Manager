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

#ifndef MAIDSAFE_PRIVATE_DATA_TYPES_H_
#define MAIDSAFE_PRIVATE_DATA_TYPES_H_

#include <memory>
#include <string>
#include <map>

#include "boost/filesystem/path.hpp"
#include "boost/functional/value_factory.hpp"
// see http://www.boost.org/doc/libs/1_51_0/libs/
// functional/factory/doc/html/index.html#boost_functional_factory.references
// for examples of using the factory types
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/rsa.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

enum class DataTypes : char {
  kDefault,
  kSignaturePacket,
  kAppendable,
  kModifiable
};

// Factory to create datatypes on request if required
class DataFactory {
 public:
  typedef std::shared_ptr<DataTypes> (*CreateDataTypeCallback)();
 private:
  typedef std::map<DataTypes, CreateDataTypeCallback> CallbackMap;
 public:
  // returns true of registration successful
  bool RegisterDataType(DataTypes data_type, CreateDataTypeCallback create_callback);
  // return true of type registered previously
  bool UnregisterDataType(DataTypes data_type);
  std::shared_ptr<DataTypes>  CreateDataType(DataTypes data_type);
};






}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DATA_TYPES_H_
