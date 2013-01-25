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

#ifndef MAIDSAFE_DATA_TYPES_DETAIL_DATA_TYPE_VALUES_H_
#define MAIDSAFE_DATA_TYPES_DETAIL_DATA_TYPE_VALUES_H_

#include <string>


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
  kImmutableDataValue,
  kMutableDataValue
};


template <typename Elem, typename Traits>
std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& ostream,
                                             const DataTagValue &data_type) {
  std::string data_type_str;
  switch (data_type) {
    case DataTagValue::kAnmidValue:
      data_type_str = "ANMID";
      break;
    case DataTagValue::kAnsmidValue:
      data_type_str = "ANSMID";
      break;
    case DataTagValue::kAntmidValue:
      data_type_str = "ANTMID";
      break;
    case DataTagValue::kAnmaidValue:
      data_type_str = "ANMAID";
      break;
    case DataTagValue::kMaidValue:
      data_type_str = "MAID";
      break;
    case DataTagValue::kPmidValue:
      data_type_str = "PMID";
      break;
    case DataTagValue::kMidValue:
      data_type_str = "MID";
      break;
    case DataTagValue::kSmidValue:
      data_type_str = "SMID";
      break;
    case DataTagValue::kTmidValue:
      data_type_str = "TMID";
      break;
    case DataTagValue::kAnmpidValue:
      data_type_str = "ANMPID";
      break;
    case DataTagValue::kMpidValue:
      data_type_str = "MPID";
      break;
    case DataTagValue::kImmutableDataValue:
      data_type_str = "Immutable Data";
      break;
    case DataTagValue::kMutableDataValue:
      data_type_str = "Mutable Data";
      break;
    default:
      data_type_str = "Invalid data type";
      break;
  }

  for (std::string::iterator itr(data_type_str.begin()); itr != data_type_str.end(); ++itr)
    ostream << ostream.widen(*itr);
  return ostream;
}

}  // namespace detail

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_DETAIL_DATA_TYPE_VALUES_H_
