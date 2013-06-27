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

#include "maidsafe/data_types/immutable_data.h"

#include "maidsafe/common/crypto.h"
#include "maidsafe/common/error.h"


namespace maidsafe {

const DataTagValue ImmutableDataTag::kEnumValue = DataTagValue::kImmutableDataValue;

ImmutableData::ImmutableData(const ImmutableData& other) : name_(other.name_), data_(other.data_) {}

ImmutableData& ImmutableData::operator=(const ImmutableData& other) {
  name_ = other.name_;
  data_ = other.data_;
  return *this;
}

ImmutableData::ImmutableData(ImmutableData&& other)
    : name_(std::move(other.name_)),
      data_(std::move(other.data_)) {}

ImmutableData& ImmutableData::operator=(ImmutableData&& other) {
  name_ = std::move(other.name_);
  data_ = std::move(other.data_);
  return *this;
}

ImmutableData::ImmutableData(const NonEmptyString& content)
    : name_(name_type(crypto::Hash<crypto::SHA512>(content))),
      data_(content) {}

ImmutableData::ImmutableData(const name_type& name,
                             const serialised_type& serialised_immutable_data)
    : name_(name),
      data_(serialised_immutable_data.data) {
  Validate();
}

void ImmutableData::Validate() const {
  if (name_.data != crypto::Hash<crypto::SHA512>(data_))
    ThrowError(CommonErrors::hashing_error);
}

ImmutableData::serialised_type ImmutableData::Serialise() const {
  return serialised_type(data_);
}

}  // namespace maidsafe
