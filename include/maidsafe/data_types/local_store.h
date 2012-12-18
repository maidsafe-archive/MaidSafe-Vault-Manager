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

#ifndef MAIDSAFE_PRIVATE_DATA_MANAGER_LOCAL_STORE_H_
#define MAIDSAFE_PRIVATE_DATA_MANAGER_LOCAL_STORE_H_

#include "maidsafe/common/types.h"
#include "maidsafe/private/data_types/type_traits.h"

class LocalStore {
public:
template  <typename T>
typename std::enable_if<is_editable<T>::value, bool>::type
  Edit(T t) {
    std::cout << " you edited me :  " << std::endl;
    return true;
  }

template<typename T>
  Get(name);

template<typename T>
  Store(name, data) {
    if(is_payapble<T>);
  }

uint_64 Lock();
std::string Validate(name, validate_data);
 private:
std::string version();
};



#endif  // MAIDSAFE_PRIVATE_DATA_MANAGER_LOCAL_STORE_H_
