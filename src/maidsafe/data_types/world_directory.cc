/*  Copyright 2013 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#include "maidsafe/data_types/world_directory.h"

#include <utility>

#include "maidsafe/common/types.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"

#include "maidsafe/data_types/directory_types.pb.h"


namespace maidsafe {

WorldDirectory::WorldDirectory(const WorldDirectory& other)
    : name_(other.name_),
      data_(other.data_) {}

WorldDirectory::WorldDirectory(WorldDirectory&& other)
    : name_(std::move(other.name_)),
      data_(std::move(other.data_)) {}

WorldDirectory& WorldDirectory::operator=(WorldDirectory other) {
  swap(*this, other);
  return *this;
}

WorldDirectory::WorldDirectory(Name name, NonEmptyString data)
    : name_(std::move(name)),
      data_(std::move(data)) {}

WorldDirectory::WorldDirectory(Name name, const serialised_type& serialised_mutable_data)
    : name_(std::move(name)),
      data_(),
      signature_() {
  protobuf::WorldDirectory proto_mutable_data;
  if (!proto_mutable_data.ParseFromString(serialised_mutable_data->string()))
    ThrowError(CommonErrors::parsing_error);
  data_ = NonEmptyString(proto_mutable_data.data());
}

WorldDirectory::serialised_type WorldDirectory::Serialise() const {
  protobuf::WorldDirectory proto_mutable_data;
  proto_mutable_data.set_data(data_.string());
  return serialised_type(NonEmptyString(proto_mutable_data.SerializeAsString()));
}

WorldDirectory::Name WorldDirectory::name() const {
  return name_;
}

NonEmptyString WorldDirectory::data() const {
  return data_;
}

void swap(WorldDirectory& lhs, WorldDirectory& rhs) {
  using std::swap;
  swap(lhs.name_, rhs.name_);
  swap(lhs.data_, rhs.data_);
}

}  // namespace maidsafe
