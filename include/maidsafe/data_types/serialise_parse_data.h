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
#include "maidsafe/common/error.h"

#ifndef MAIDSAFE_PRIVATE_DATA_MANAGER_SERIALISE_PARSE_DATA_H_
#define MAIDSAFE_PRIVATE_DATA_MANAGER_SERIALISE_PARSE_DATA_H_
namespace maidsafe {

template <T>
auto GetType(int type_number) {
  switch (type_number) {
    case  0: return decltype TaggedValue<Identity, passport::detail::AnmidTag>();
    case  1: return decltype(TaggedValue<Identity, passport::detail::AnsmidTag>());
    case  2: return decltype(TaggedValue<Identity, passport::detail::AntmidTag>());
    case  3: return decltype(TaggedValue<Identity, passport::detail::AnmaidTag>());
    case  4: return decltype(TaggedValue<Identity, passport::detail::MaidTag>());
    case  5: return decltype(TaggedValue<Identity, passport::detail::PmidTag>());
    case  6: return decltype(TaggedValue<Identity, passport::detail::MidTag>());
    case  7: return decltype(TaggedValue<Identity, passport::detail::SmidTag>());
    case  8: return decltype(TaggedValue<Identity, passport::detail::TmidTag>());
    case  9: return decltype(TaggedValue<Identity, passport::detail::AnmpidTag>());
    case 10: return decltype(TaggedValue<Identity, passport::detail::MpidTag>());
    case 11: return decltype(ImmutableData());
    case 12: return decltype(MutableData());
    default :
             ThrowError(maidsafe::CommonErrors::unknown);  // TODO(dirvine) FIXME
  }
}

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_DATA_MANAGER_H_

