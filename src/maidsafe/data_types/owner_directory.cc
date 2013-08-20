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

#include "maidsafe/data_types/owner_directory.h"

#include <utility>

#include "maidsafe/common/types.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"

#include "maidsafe/data_types/directory_types.pb.h"


namespace maidsafe {

OwnerDirectory::OwnerDirectory(const OwnerDirectory& other)
    : name_(other.name_),
      data_(other.data_) {}

OwnerDirectory::OwnerDirectory(OwnerDirectory&& other)
    : name_(std::move(other.name_)),
      data_(std::move(other.data_)) {}

OwnerDirectory& OwnerDirectory::operator=(OwnerDirectory other) {
  swap(*this, other);
  return *this;
}

OwnerDirectory::OwnerDirectory(const Name& name,
                               const NonEmptyString& data)
    : name_(name),
      data_(data) {}

OwnerDirectory::OwnerDirectory(const Name& name, const serialised_type& serialised_mutable_data)
    : name_(name),
      data_() {
  protobuf::OwnerDirectory proto_mutable_data;
  if (!proto_mutable_data.ParseFromString(serialised_mutable_data->string()))
    ThrowError(CommonErrors::parsing_error);
  data_ = NonEmptyString(proto_mutable_data.data());
}

OwnerDirectory::serialised_type OwnerDirectory::Serialise() const {
  protobuf::OwnerDirectory proto_mutable_data;
  proto_mutable_data.set_data(data_.string());
  return serialised_type(NonEmptyString(proto_mutable_data.SerializeAsString()));
}

OwnerDirectory::Name OwnerDirectory::name() const {
  return name_;
}

NonEmptyString OwnerDirectory::data() const {
  return data_;
}

void swap(OwnerDirectory& lhs, OwnerDirectory& rhs) {
  using std::swap;
  swap(lhs.name_, rhs.name_);
  swap(lhs.data_, rhs.data_);
}

}  // namespace maidsafe
