/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
