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

#include <string>

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
  return (EncodeToBase32(result.second) + '_' +
          std::to_string(static_cast<uint32_t>(result.first)));
}

DataNameVariant GetDataNameVariant(const fs::path& file_name) {
  std::string file_name_str(file_name.string());
  size_t index(file_name_str.rfind('_'));
  auto id(static_cast<DataTagValue>(std::stoul(file_name_str.substr(index + 1))));
  Identity key_id(DecodeFromBase32(file_name_str.substr(0, index)));
  return GetDataNameVariant(id, key_id);
}

}  // namespace detail

}  // namespace data_store

}  // namespace maidsafe
