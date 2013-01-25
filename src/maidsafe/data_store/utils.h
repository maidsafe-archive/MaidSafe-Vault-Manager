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

#ifndef MAIDSAFE_DATA_STORE_UTILS_H_
#define MAIDSAFE_DATA_STORE_UTILS_H_

#include "boost/filesystem/path.hpp"

#include "maidsafe/data_types/data_name_variant.h"


namespace maidsafe {

namespace data_store {

namespace detail {

boost::filesystem::path GetFileName(const DataNameVariant& data_name_variant);

DataNameVariant GetDataNameVariant(const boost::filesystem::path& file_name);

}  // namespace detail

}  // namespace data_store

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_STORE_UTILS_H_
