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
#include "maidsafe/common/on_scope_exit.h"

#include "maidsafe/data_types/structured_data_version.pb.h"


namespace maidsafe {

StructuredDataVersions::Details::Details() : parent(), child_count(0) {}

StructuredDataVersions::Details::Details(const Details& other)
    : parent(other.parent),
      child_count(other.child_count) {}

StructuredDataVersions::Details::Details(Details&& other)
    : parent(std::move(other.parent)),
      child_count(std::move(other.child_count)) {}

StructuredDataVersions::Details& StructuredDataVersions::Details::operator=(Details other) {
  swap(*this, other);
  return *this;
}

void swap(StructuredDataVersions::Details& lhs,
          StructuredDataVersions::Details& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.parent, rhs.parent);
  swap(lhs.child_count, rhs.child_count);
}



StructuredDataVersions::StructuredDataVersions(uint32_t max_versions, uint32_t max_branches)
    : max_versions_(max_versions),
      max_branches_(max_branches),
      versions_(),
      root_(std::end(versions_)),
      tips_of_trees_(),
      orphans_() {
  if (max_versions_ < 1U || max_branches_ < 1U)
    ThrowError(CommonErrors::invalid_parameter);
}

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
      root_(),
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
  // Check 'new_version' doesn't already exist.
  auto existing_itr(versions_.find(new_version));
  if (existing_itr != std::end(versions_)) {
    if (existing_itr->second.parent->first == old_version)
      return;
    else
      ThrowError(CommonErrors::invalid_parameter);
  }

  // Handle inserting root version.
  if (!old_version->IsInitialised())
    return InsertRoot(new_version);

  // Find parent and insert as child or as orphan if not found
  auto parent_itr(versions_.find(old_version));
  if (parent_itr == std::end(versions_))
    InsertOrphan(new_version);
  else
    InsertChild(new_version, parent_itr);
}

std::vector<StructuredDataVersions::VersionName> StructuredDataVersions::Get() const {
  std::vector<StructuredDataVersions::VersionName> result;
  for (const auto& tot : tips_of_trees_) {
    assert(tot->second.child_count == 0U);
    result.push_back(tot->first);
  }
  return result;
}

std::vector<StructuredDataVersions::VersionName> StructuredDataVersions::GetBranch(
    const VersionName& branch_tip) const {
  auto branch_tip_itr(FindBranchTip(branch_tip));
  CheckBranchTipIterator(branch_tip, branch_tip_itr);
  auto itr(*branch_tip_itr);
  std::vector<StructuredDataVersions::VersionName> result;
  while (itr != std::end(versions_)) {
    result.push_back(itr->first);
    itr = itr->second.parent;
  }
  return result;
}

void StructuredDataVersions::DeleteBranchUntilFork(const VersionName& branch_tip) {
  auto branch_tip_itr(FindBranchTip(branch_tip));
  CheckBranchTipIterator(branch_tip, branch_tip_itr);
  auto itr(*branch_tip_itr);
  tips_of_trees_.erase(branch_tip_itr);

  for (;;) {
    auto parent_itr = itr->second.parent;
    if (parent_itr == std::end(versions_)) {
      // Found root or orphan.  Either way, we're at the end of the branch.
      EraseRootOrOrphanOfBranch(itr);
      versions_.erase(itr);
      return;
    }

    versions_.erase(itr);
    if (--parent_itr->second.child_count > 0U)
      return;  // Found fork.

    itr = parent_itr;
  }
}

void StructuredDataVersions::EraseRootOrOrphanOfBranch(VersionsItr itr) {
  assert(itr->second.parent == std::end(versions_));
  if (itr == root_) {
    // If we're erasing root, try to assign an orphan as the new root.
    if (orphans_.empty()) {
      root_ = std::end(versions_);
    } else {
      root_ = orphans_.back().second;
      orphans_.pop_back();
    }
  } else {
    orphans_.erase(std::remove_if(std::begin(orphans_),
                                  std::end(orphans_),
                                  [itr](const Orphan& orphan) { return orphan.second == itr; }),
                   std::end(orphans_));
  }
}

void StructuredDataVersions::InsertRoot(const VersionName& root_name) {
  // Construct temp object before modifying members in case make_pair throws.
  Version root_version(std::make_pair(root_name, Details()));
  root_version.second.parent = std::end(versions_);

  if (versions_.size() == 1U && max_versions_ == 1U)
    versions_.clear();

  if (versions_.empty()) {
    versions_.insert(root_version);
    root_ = std::begin(versions_);
    tips_of_trees_.push_back(std::begin(versions_));
    return;
  }

  // This is only valid if root_ == end().
  if (root_ != std::end(versions_))
    ThrowError(CommonErrors::invalid_parameter);

  auto orphan_itr(FindOrphanOf(root_name));
  bool will_create_new_branch(orphan_itr == std::end(orphans_));
  if (will_create_new_branch && AtBranchesLimit())
    ThrowError(CommonErrors::cannot_exceed_limit);

  if (AtVersionsLimit()) {
    // If the new root was inserted, we'd exceed max_versions_, and then we'd remove the root as
    // normal to bring the count within the limit again.  Skip the insert and if the new root is the
    // parent of an orphan, mark the orphan as the root.
    if (orphan_itr == std::end(orphans_))
      return;
    orphan_itr->second->second.parent = std::end(versions_);
    root_ = orphan_itr->second;
    orphans_.erase(orphan_itr);
  } else {
    // This should always succeed since we've already checked the new version doesn't exist.
    auto result(versions_.insert(root_version));
    assert(result.second);
    root_ = result.first;
    if (orphan_itr != std::end(orphans_)) {
      orphan_itr->second->second.parent = root_;
      orphans_.erase(orphan_itr);
    }
  }
}

void StructuredDataVersions::InsertChild(const VersionName& child_name, VersionsItr parent_itr) {
  // Construct temp object before modifying members in case make_pair throws.
  Version child_version(std::make_pair(child_name, Details()));
  child_version.second.parent = parent_itr;

  //check we aren't going to exceed the limits

  //see if we've un-orphaned any orphans

}

void StructuredDataVersions::InsertOrphan(const VersionName& child_name) {
  // Check we aren't going to exceed the limits
  if (AtBranchesLimit())
    ThrowError(CommonErrors::cannot_exceed_limit);
  if (AtVersionsLimit())
    ThrowError(CommonErrors::unable_to_handle_request);

  // Construct temp object before modifying members in case make_pair throws.
  Version child_version(std::make_pair(child_name, Details()));
  child_version.second.parent = std::end(versions_);

  //see if we've un-orphaned any orphans
}

std::vector<StructuredDataVersions::VersionsItr>::iterator StructuredDataVersions::FindBranchTip(
    const VersionName& name) {
  return std::find_if(std::begin(tips_of_trees_), std::end(tips_of_trees_),
                      [&name](VersionsItr branch_tip) { return branch_tip->first == name; });
}

std::vector<StructuredDataVersions::VersionsItr>::const_iterator
    StructuredDataVersions::FindBranchTip(const VersionName& name) const {
  return std::find_if(std::begin(tips_of_trees_), std::end(tips_of_trees_),
                      [&name](VersionsItr branch_tip) { return branch_tip->first == name; });
}

void StructuredDataVersions::CheckBranchTipIterator(
    const VersionName& name,
    std::vector<VersionsItr>::const_iterator branch_tip_itr) const {
  if (branch_tip_itr == std::end(tips_of_trees_)) {
    if (versions_.find(name) == std::end(versions_))
      ThrowError(CommonErrors::no_such_element);
    else
      ThrowError(CommonErrors::invalid_parameter);
  }
}

std::vector<StructuredDataVersions::Orphan>::iterator StructuredDataVersions::FindOrphanOf(
    const VersionName& name) {
  return std::find_if(std::begin(orphans_), std::end(orphans_),
                      [&name](const Orphan& orphan) { return orphan.first == name; });
}

std::vector<StructuredDataVersions::Orphan>::const_iterator StructuredDataVersions::FindOrphanOf(
    const VersionName& name) const {
  return std::find_if(std::begin(orphans_), std::end(orphans_),
                      [&name](const Orphan& orphan) { return orphan.first == name; });
}

bool StructuredDataVersions::AtVersionsLimit() const {
  assert(versions_.size() <= max_versions_);
  return versions_.size() == max_versions_;
}

bool StructuredDataVersions::AtBranchesLimit() const {
  assert(tips_of_trees_.size() <= max_branches_);
  return tips_of_trees_.size() == max_branches_;
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

}  // namespace maidsafe
