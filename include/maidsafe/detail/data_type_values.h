/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#ifndef MAIDSAFE_DETAIL_DATA_TYPE_VALUES_H_
#define MAIDSAFE_DETAIL_DATA_TYPE_VALUES_H_

namespace maidsafe {

namespace detail {

enum class DataTagValue {
  kAnmidValue,
  kAnsmidValue,
  kAntmidValue,
  kAnmaidValue,
  kMaidValue,
  kPmidValue,
  kMidValue,
  kSmidValue,
  kTmidValue,
  kAnmpidValue,
  kMpidValue,
  kImmutableDataValue
};

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_DETAIL_DATA_TYPE_VALUES_H_
