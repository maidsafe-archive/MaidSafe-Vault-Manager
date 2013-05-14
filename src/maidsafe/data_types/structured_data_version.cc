/***************************************************************************************************
 *  Copyright 2013 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "maidsafe/data_types/structured_data_version.h"

#include "maidsafe/common/error.h"

#include "maidsafe/data_types/structured_data_version.pb.h"


namespace maidsafe {

StructuredDataVersions::Version::Version(const VersionName& name_in)
    : name(name_in),
      parent(),
      child_count(0) {
  if (!name->IsInitialised())
    ThrowError(CommonErrors::invalid_parameter);
}

StructuredDataVersions::Version::Version(const Version& other)
    : name(other.name),
      parent(other.parent),
      child_count(other.child_count) {}

StructuredDataVersions::Version::Version(Version&& other)
    : name(std::move(other.name)),
      parent(std::move(other.parent)),
      child_count(std::move(other.child_count)) {}

StructuredDataVersions::Version& StructuredDataVersions::Version::operator=(Version other) {
  swap(*this, other);
  return *this;
}

void swap(StructuredDataVersions::Version& lhs,
          StructuredDataVersions::Version& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.name, rhs.name);
  swap(lhs.parent, rhs.parent);
  swap(lhs.child_count, rhs.child_count);
}



StructuredDataVersions::StructuredDataVersions(uint32_t max_versions, uint32_t max_branches)
    : max_versions_(max_versions),
      max_branches_(max_branches),
      versions_(),
      root_(std::end(versions_)),
      tips_of_trees_(),
      orphans_() {}

StructuredDataVersions::StructuredDataVersions(const StructuredDataVersions& other)
    : max_versions_(other.max_versions_),
      max_branches_(other.max_branches_),
      versions_(other.versions_),
      root_(other.root_),
      tips_of_trees_(other.tips_of_trees_),
      orphans_(other.orphans_) {}

StructuredDataVersions::StructuredDataVersions(StructuredDataVersions&& other)
    : max_versions_(std::move(other.max_versions_)),
      max_branches_(std::move(other.max_branches_)),
      versions_(std::move(other.versions_)),
      root_(std::move(other.root_)),
      tips_of_trees_(std::move(other.tips_of_trees_)),
      orphans_(std::move(other.orphans_)) {}


StructuredDataVersions& StructuredDataVersions::operator=(StructuredDataVersions other) {
  swap(*this, other);
  return *this;
}

StructuredDataVersions::StructuredDataVersions(const serialised_type& serialised_data_versions)
    : max_versions_(),
      max_branches_(),
      versions_(),
      tips_of_trees_(),
      orphans_() {
  protobuf::StructuredDataVersions proto_versions;
  if (!proto_versions.ParseFromString(serialised_data_versions->string()))
    ThrowError(CommonErrors::parsing_error);

}

StructuredDataVersions::serialised_type StructuredDataVersions::Serialise() const {
  protobuf::StructuredDataVersions proto_versions;


  return serialised_type(NonEmptyString(proto_versions.SerializeAsString()));
}

void StructuredDataVersions::Put(const VersionName& old_version, const VersionName& new_version) {
  Version version(new_version);
  if (!old_version->IsInitialised()) {
    if (!versions_.empty())
      ThrowError(CommonErrors::invalid_parameter);
    version.parent = std::end(versions_);
    versions_.insert(version);
    root_ = std::begin(versions_);
    tips_of_trees_.push_back(std::begin(versions_));
  }


}

std::vector<StructuredDataVersions::VersionName> StructuredDataVersions::Get() const {
  std::vector<StructuredDataVersions::VersionName> result;


  return result;
}

std::vector<StructuredDataVersions::VersionName> StructuredDataVersions::GetBranch(
    const VersionName& /*branch_tip*/) const {
  std::vector<StructuredDataVersions::VersionName> result;


  return result;
}

void StructuredDataVersions::DeleteBranch(const VersionName& /*branch_tip*/) {
}

void StructuredDataVersions::Validate() const {
  //if (max_versions_ < versions_.size() || max_branches_ < tips_of_trees_.size())
  //  ThrowError(CommonErrors::invalid_parameter);
}

void swap(StructuredDataVersions& lhs, StructuredDataVersions& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.max_versions_, rhs.max_versions_);
  swap(lhs.max_branches_, rhs.max_branches_);
  swap(lhs.versions_, rhs.versions_);
  swap(lhs.root_, rhs.root_);
  swap(lhs.tips_of_trees_, rhs.tips_of_trees_);
  swap(lhs.orphans_, rhs.orphans_);
}

bool operator<(const StructuredDataVersions::Version& lhs,
               const StructuredDataVersions::Version& rhs) {
  return lhs.name < rhs.name;
}

}  // namespace maidsafe
