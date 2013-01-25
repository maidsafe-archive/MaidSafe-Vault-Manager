/***************************************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use.  The use of this code is governed by the licence file licence.txt found in the root of    *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit         *
 *  written permission of the board of directors of MaidSafe.net.                                  *
 **************************************************************************************************/

#include "maidsafe/data_store/utils.h"

#include "boost/variant/apply_visitor.hpp"

#include "maidsafe/common/error.h"
#include "maidsafe/common/utils.h"


namespace fs = boost::filesystem;

namespace maidsafe {

namespace data_store {

namespace detail {

fs::path GetFileName(const DataNameVariant& data_name_variant) {
  auto result(boost::apply_visitor(maidsafe::detail::GetTagValueAndIdentity(), data_name_variant));
  return (EncodeToBase32(result.second) + '_' + std::to_string(static_cast<int>(result.first)));
}

DataNameVariant GetDataNameVariant(const fs::path& file_name) {
  std::string file_name_str(file_name.string());
  size_t index(file_name_str.rfind('_'));
  maidsafe::detail::DataTagValue id(
      static_cast<maidsafe::detail::DataTagValue>(std::stoi(file_name_str.substr(index + 1))));
  Identity key_id(DecodeFromBase32(file_name_str.substr(0, index)));
  switch (id) {
    case maidsafe::detail::DataTagValue::kAnmidValue:
      return passport::PublicAnmid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kAnsmidValue:
      return passport::PublicAnsmid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kAntmidValue:
      return passport::PublicAntmid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kAnmaidValue:
      return passport::PublicAnmaid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kMaidValue:
      return passport::PublicMaid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kPmidValue:
      return passport::PublicPmid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kMidValue:
      return passport::Mid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kSmidValue:
      return passport::Smid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kTmidValue:
      return passport::Tmid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kAnmpidValue:
      return passport::PublicAnmpid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kMpidValue:
      return passport::PublicMpid::name_type(key_id);
    case maidsafe::detail::DataTagValue::kImmutableDataValue:
      return ImmutableData::name_type(key_id);
    case maidsafe::detail::DataTagValue::kMutableDataValue:
      return MutableData::name_type(key_id);
    default: {
      ThrowError(CommonErrors::invalid_parameter);
      return DataNameVariant();
    }
  }
}

}  // namespace detail

}  // namespace data_store

}  // namespace maidsafe
