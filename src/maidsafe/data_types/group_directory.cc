/* Copyright 2013 MaidSafe.net limited

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

#include "maidsafe/data_types/group_directory.h"

#include <utility>

#include "maidsafe/common/types.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"

#include "maidsafe/data_types/directory_types.pb.h"


namespace maidsafe {

GroupDirectory::GroupDirectory(const GroupDirectory& other)
    : name_(other.name_),
      data_(other.data_),
      signature_(other.signature_) {}

GroupDirectory::GroupDirectory(GroupDirectory&& other)
    : name_(std::move(other.name_)),
      data_(std::move(other.data_)),
      signature_(std::move(other.signature_)) {}

GroupDirectory& GroupDirectory::operator=(GroupDirectory other) {
  swap(*this, other);
  return *this;
}

GroupDirectory::GroupDirectory(const Name& name, const NonEmptyString& data)
    : name_(name),
      data_(data),
      signature_() {}

GroupDirectory::GroupDirectory(const Name& name,
                               const NonEmptyString& data,
                               const asymm::PrivateKey& signing_key)
    : name_(name),
      data_(data),
      signature_(asymm::Sign(data, signing_key)) {}

GroupDirectory::GroupDirectory(const Name& name, const serialised_type& serialised_mutable_data)
    : name_(name),
      data_(),
      signature_() {
  protobuf::GroupDirectory proto_mutable_data;
  if (!proto_mutable_data.ParseFromString(serialised_mutable_data->string()))
    ThrowError(CommonErrors::parsing_error);
  data_ = NonEmptyString(proto_mutable_data.data());
  if (proto_mutable_data.has_signature())
    signature_ = asymm::Signature(proto_mutable_data.signature());
}

GroupDirectory::serialised_type GroupDirectory::Serialise() const {
  protobuf::GroupDirectory proto_mutable_data;
  proto_mutable_data.set_data(data_.string());
  if (signature_.IsInitialised())
    proto_mutable_data.set_signature(signature_.string());
  return serialised_type(NonEmptyString(proto_mutable_data.SerializeAsString()));
}

void swap(GroupDirectory& lhs, GroupDirectory& rhs) {
  using std::swap;
  swap(lhs.name_, rhs.name_);
  swap(lhs.data_, rhs.data_);
  swap(lhs.signature_, rhs.signature_);
}

}  // namespace maidsafe
