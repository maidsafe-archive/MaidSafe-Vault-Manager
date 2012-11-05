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

#ifndef MAIDSAFE_PRIVATE_DATA_MANAGER_TYPE_TRAITS_H_
#define MAIDSAFE_PRIVATE_DATA_MANAGER_TYPE_TRAITS_H_

#include "maidsafe/common/types.h"
#include "maidsafe/private/utils/fob.h"

// traits
//
template <typename T>
struct is_editable {
  static const bool value = false;
};

template <>
struct is_editable<MutableData> {
  static const bool value = true;
};

template <typename T>
struct is_appendable {
  static const bool value = false;
};

template <>
struct is_appendable<AppendableData> {
  static const bool value = false;
};

template <typename T>
struct is_cacheable {
  static const bool value = false;
};

template <>
struct is_cacheable<ImmutableData> {
  static const bool value = true;
};

#endif  // MAIDSAFE_PRIVATE_DATA_MANAGER_TYPE_TRAITS_H_
