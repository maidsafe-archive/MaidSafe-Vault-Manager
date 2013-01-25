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
  auto result(boost::apply_visitor(GetTagValueAndIdentityVisitor(), data_name_variant));
  return (EncodeToBase32(result.second) + '_' + std::to_string(static_cast<int>(result.first)));
}

DataNameVariant GetDataNameVariant(const fs::path& file_name) {
  std::string file_name_str(file_name.string());
  size_t index(file_name_str.rfind('_'));
  auto id(static_cast<DataTagValue>(std::stoi(file_name_str.substr(index + 1))));
  Identity key_id(DecodeFromBase32(file_name_str.substr(0, index)));
  return GetDataNameVariant(id, key_id);
}

}  // namespace detail

}  // namespace data_store

}  // namespace maidsafe
