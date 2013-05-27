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

#include "maidsafe/data_types/structured_data_versions.h"

#include <algorithm>
#include <limits>

#include "maidsafe/common/error.h"
#include "maidsafe/common/on_scope_exit.h"

#include "maidsafe/data_types/structured_data_versions.pb.h"


namespace maidsafe {

StructuredDataVersions::VersionName::VersionName()
    : index(std::numeric_limits<uint64_t>::max()),
      id() {}

StructuredDataVersions::VersionName::VersionName(uint32_t index_in,
                                                 const ImmutableData::name_type& id_in)
    : index(index_in),
      id(id_in) {}

StructuredDataVersions::VersionName::VersionName(const VersionName& other)
    : index(other.index),
      id(other.id) {}

StructuredDataVersions::VersionName::VersionName(VersionName&& other)
    : index(std::move(other.index)),
      id(std::move(other.id)) {}

StructuredDataVersions::VersionName& StructuredDataVersions::VersionName::operator=(
    VersionName other) {
  swap(*this, other);
  return *this;
}

void swap(StructuredDataVersions::VersionName& lhs,
          StructuredDataVersions::VersionName& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.index, rhs.index);
  swap(lhs.id, rhs.id);
}

bool operator==(const StructuredDataVersions::VersionName& lhs,
                const StructuredDataVersions::VersionName& rhs) {
  return std::tie(lhs.index, lhs.id) == std::tie(rhs.index, rhs.id);
}

bool operator!=(const StructuredDataVersions::VersionName& lhs,
                const StructuredDataVersions::VersionName& rhs) {
  return !operator==(lhs, rhs);
}

bool operator<(const StructuredDataVersions::VersionName& lhs,
               const StructuredDataVersions::VersionName& rhs) {
  return std::tie(lhs.index, lhs.id) < std::tie(rhs.index, rhs.id);
}

bool operator>(const StructuredDataVersions::VersionName& lhs,
               const StructuredDataVersions::VersionName& rhs) {
  return operator< (rhs, lhs);
}

bool operator<=(const StructuredDataVersions::VersionName& lhs,
                const StructuredDataVersions::VersionName& rhs) {
  return !operator> (lhs, rhs);
}

bool operator>=(const StructuredDataVersions::VersionName& lhs,
                const StructuredDataVersions::VersionName& rhs) {
  return !operator< (lhs, rhs);
}



StructuredDataVersions::Details::Details() : parent(), children() {}

StructuredDataVersions::Details::Details(VersionsItr parent_in) : parent(parent_in), children() {}

StructuredDataVersions::Details::Details(const Details& other)
    : parent(other.parent),
      children(other.children) {}

StructuredDataVersions::Details::Details(Details&& other)
    : parent(std::move(other.parent)),
      children(std::move(other.children)) {}

StructuredDataVersions::Details& StructuredDataVersions::Details::operator=(Details other) {
  swap(*this, other);
  return *this;
}

void swap(StructuredDataVersions::Details& lhs,
          StructuredDataVersions::Details& rhs) MAIDSAFE_NOEXCEPT {
  using std::swap;
  swap(lhs.parent, rhs.parent);
  swap(lhs.children, rhs.children);
}



StructuredDataVersions::StructuredDataVersions(uint32_t max_versions, uint32_t max_branches)
    : max_versions_(max_versions),
      max_branches_(max_branches),
      versions_(),
      root_(std::make_pair(VersionName(), std::end(versions_))),
      tips_of_trees_(),
      orphans_() {
  ValidateLimits();
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

  max_versions_ = proto_versions.max_versions();
  max_branches_ = proto_versions.max_branches();
  ValidateLimits();


}

StructuredDataVersions::serialised_type StructuredDataVersions::Serialise() const {
  protobuf::StructuredDataVersions proto_versions;
  proto_versions.set_max_versions(max_versions_);
  proto_versions.set_max_branches(max_branches_);

  BranchToProtobuf(root_.second, proto_versions.add_branch());
  for (const auto& orphan : orphans_)
    BranchToProtobuf(orphan.second, proto_versions.add_branch());

  return serialised_type(NonEmptyString(proto_versions.SerializeAsString()));
}

void StructuredDataVersions::BranchToProtobuf(
    VersionsItr /*itr*/,
    protobuf::StructuredDataVersions_Branch* /*proto_branch*/) const {
}


void StructuredDataVersions::ApplySerialised(const serialised_type& serialised_data_versions) {
  StructuredDataVersions new_info(serialised_data_versions);

}

void StructuredDataVersions::Put(const VersionName& old_version, const VersionName& new_version) {
  if (NewVersionPreExists(old_version, new_version))
    return;

  // Check we've not been asked to store two roots.
  bool is_root(!old_version.id->IsInitialised());
  if (is_root && root_.second != std::end(versions_) && !RootParentName().id->IsInitialised())
    ThrowError(CommonErrors::invalid_parameter);

  // Construct temp objects before modifying members in case exception is thrown.
  Version version(std::make_pair(new_version,
      std::make_shared<Details>(is_root ? std::end(versions_) : versions_.find(old_version))));
  bool is_orphan(version.second->parent == std::end(versions_) && !is_root);
  OrphansRange orphans_range;
  bool unorphans_existing_root(false);
  CheckForUnorphaning(old_version, version, orphans_range, unorphans_existing_root);
  auto unorphaned_count(std::distance(orphans_range.first, orphans_range.second));

  // Handle case where we're about to exceed 'max_versions_'.
  bool erase_existing_root(false);
  if (AtVersionsLimit()) {
    if (unorphans_existing_root || is_root)
      // This new version would become 'root_', only to be immediately erased to bring version count
      // back down to 'max_versions_'.
      return;
    erase_existing_root = true;
  }

  // Handle case where we're about to exceed 'max_branches_'.
  CheckBranchCount(version, is_orphan, unorphaned_count, erase_existing_root);

  // Finally, safe to now add details
  Insert(version, is_root, is_orphan, old_version, unorphans_existing_root, orphans_range,
         erase_existing_root);
}

void StructuredDataVersions::ValidateLimits() const {
  if (max_versions_ < 1U || max_branches_ < 1U)
    ThrowError(CommonErrors::invalid_parameter);
}

StructuredDataVersions::VersionName StructuredDataVersions::ParentName(VersionsItr itr) const {
  return itr->second->parent->first;
}

StructuredDataVersions::VersionName StructuredDataVersions::ParentName(
    Versions::const_iterator itr) const {
  return itr->second->parent->first;
}

StructuredDataVersions::VersionName StructuredDataVersions::RootParentName() const {
  return root_.first;
}

bool StructuredDataVersions::NewVersionPreExists(const VersionName& old_version,
                                                 const VersionName& new_version) const {
  auto existing_itr(versions_.find(new_version));
  if (existing_itr != std::end(versions_)) {
    if (existing_itr->second->parent != std::end(versions_) &&
        ParentName(existing_itr) == old_version) {
      return true;
    } else {
      ThrowError(CommonErrors::invalid_parameter);
    }
  }
  return false;
}

void StructuredDataVersions::CheckForUnorphaning(const VersionName& old_version,
                                                 Version& version,
                                                 OrphansRange& orphans_range,
                                                 bool& unorphans_existing_root) const {
  orphans_range = orphans_.equal_range(version.first);
  std::vector<std::future<void>> check_futures;
  for (auto orphan_itr(orphans_range.first); orphan_itr != orphans_range.second; ++orphan_itr) {
    // Check we can't iterate back to ourself (avoid circular parent-child chain)
    check_futures.push_back(CheckVersionNotInBranch(orphan_itr->second, version.first));
    version.second->children.emplace_back(orphan_itr->second);
  }
  unorphans_existing_root = (root_.first.id->IsInitialised() && RootParentName() == old_version);
  assert(!(std::distance(orphans_range.first, orphans_range.second) != 0 &&
           unorphans_existing_root));
  for (auto& check_future : check_futures)
    check_future.get();
}

std::future<void> StructuredDataVersions::CheckVersionNotInBranch(
    VersionsItr itr,
    const VersionName& version) const {
  return std::async([this, itr, &version]() {
      VersionsItr versions_itr(itr);
      while (versions_itr != std::end(versions_)) {
        auto child_itr(std::begin(versions_itr->second->children));
        if (child_itr == std::end(versions_itr->second->children))
          return;
        if ((*child_itr)->first == version)
          ThrowError(CommonErrors::invalid_parameter);
        std::vector<std::future<void>> check_futures;
        while (++child_itr != std::end(versions_itr->second->children))
          check_futures.emplace_back(CheckVersionNotInBranch(*child_itr, version));
        versions_itr = *std::begin(versions_itr->second->children);
        for (auto& check_future : check_futures)
          check_future.get();
      }
  });
}

void StructuredDataVersions::CheckBranchCount(const Version& version,
                                              bool is_orphan,
                                              size_t unorphaned_count,
                                              bool& erase_existing_root) const {
  if (AtBranchesLimit() && unorphaned_count == 0) {
    if (is_orphan || !version.second->parent->second->children.empty()) {
      // We're going to exceed limit - see if deleting 'root_' helps
      bool root_is_tip_of_tree(root_.second != std::end(versions_) &&
                               root_.second->second->children.empty());
      if (root_is_tip_of_tree)
        erase_existing_root = true;
      else
        ThrowError(CommonErrors::cannot_exceed_limit);
    }
  }
}

void StructuredDataVersions::Insert(const Version& version,
                                    bool is_root,
                                    bool is_orphan,
                                    const VersionName& old_version,
                                    bool unorphans_existing_root,
                                    OrphansRange orphans_range,
                                    bool erase_existing_root) {
  auto inserted_itr(versions_.insert(version).first);

  if (!is_root && !is_orphan)
    SetVersionAsChildOfItsParent(inserted_itr);

  if (is_orphan)
    orphans_.insert(std::make_pair(old_version, inserted_itr));

  if (is_root) {
    assert(!erase_existing_root);
    root_ = std::make_pair(old_version, inserted_itr);
  } else if (unorphans_existing_root) {
    assert(!erase_existing_root);
    root_.second->second->parent = inserted_itr;
    root_ = std::make_pair(old_version, inserted_itr);
  } else {
    Unorphan(inserted_itr, orphans_range);
  }

  if (erase_existing_root) {
    assert(!unorphans_existing_root && !is_root);
    ReplaceRoot();
  }

  if (version.second->children.empty())
    tips_of_trees_.push_back(inserted_itr);

  assert(versions_.size() <= max_versions_ && tips_of_trees_.size() <= max_branches_);
}

void StructuredDataVersions::SetVersionAsChildOfItsParent(VersionsItr versions_itr) {
  auto& parents_children(versions_itr->second->parent->second->children);
  if (parents_children.empty()) {
    auto tip_of_tree_itr(std::find_if(std::begin(tips_of_trees_),
                                      std::end(tips_of_trees_),
                                      [this, versions_itr](VersionsItr tot) {
                                          return tot->first == ParentName(versions_itr);
                                      }));
    assert(tip_of_tree_itr != std::end(tips_of_trees_));
    tips_of_trees_.erase(tip_of_tree_itr);
  }
  parents_children.push_back(versions_itr);
}

void StructuredDataVersions::Unorphan(VersionsItr parent, OrphansRange orphans_range) {
  while (orphans_range.first != orphans_range.second) {
    orphans_range.first->second->second->parent = parent;
    orphans_range.first = orphans_.erase(orphans_range.first);
  }
}

void StructuredDataVersions::ReplaceRoot() {
  // Remove current root from 'tips_of_trees_'.
  auto tip_of_tree_itr(FindBranchTip(root_.second->first));
  if (tip_of_tree_itr != std::end(tips_of_trees_))
    tips_of_trees_.erase(tip_of_tree_itr);

  if (root_.second->second->children.empty())
    ReplaceRootFromOrphans();
  else
    ReplaceRootFromChildren();
}

void StructuredDataVersions::ReplaceRootFromOrphans() {
  assert(!orphans_.empty());
  auto replacement_itr(std::min_element(
      std::begin(orphans_),
      std::end(orphans_),
      [](const Orphans::value_type& lhs_orphan, const Orphans::value_type& rhs_orphan) {
          return lhs_orphan.second->first < rhs_orphan.second->first;
      }));
  versions_.erase(root_.second);
  root_.first = replacement_itr->first;
  root_.second = replacement_itr->second;
  orphans_.erase(replacement_itr);
}

void StructuredDataVersions::ReplaceRootFromChildren() {
  // Create orphans and find replacement from current root's children.
  auto current_root_name(root_.second->first);
  auto replacement_candidate(std::make_pair(current_root_name,
                                            root_.second->second->children.front()));
  replacement_candidate.second->second->parent = std::end(versions_);
  for (auto child : root_.second->second->children) {
    child->second->parent = std::end(versions_);
    if (child->first < replacement_candidate.second->first) {
      orphans_.insert(replacement_candidate);
      replacement_candidate.second = child;
    } else if (child->first > replacement_candidate.second->first) {
      orphans_.insert(std::make_pair(current_root_name, child));
    }
  }
  versions_.erase(root_.second);
  root_ = replacement_candidate;
}

std::vector<StructuredDataVersions::VersionsItr>::const_iterator
    StructuredDataVersions::FindBranchTip(const VersionName& name) const {
  return std::find_if(std::begin(tips_of_trees_), std::end(tips_of_trees_),
                      [&name](VersionsItr branch_tip) { return branch_tip->first == name; });
}

std::vector<StructuredDataVersions::VersionsItr>::iterator
    StructuredDataVersions::FindBranchTip(const VersionName& name) {
  return std::find_if(std::begin(tips_of_trees_), std::end(tips_of_trees_),
                      [&name](VersionsItr branch_tip) { return branch_tip->first == name; });
}

std::vector<StructuredDataVersions::VersionName> StructuredDataVersions::Get() const {
  std::vector<StructuredDataVersions::VersionName> result;
  for (const auto& tot : tips_of_trees_) {
    assert(tot->second->children.empty());
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
    itr = itr->second->parent;
  }
  return result;
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

void StructuredDataVersions::DeleteBranchUntilFork(const VersionName& branch_tip) {
  auto branch_tip_itr(FindBranchTip(branch_tip));
  CheckBranchTipIterator(branch_tip, branch_tip_itr);
  auto itr(*branch_tip_itr);
  tips_of_trees_.erase(branch_tip_itr);

  for (;;) {
    auto parent_itr = itr->second->parent;
    if (parent_itr == std::end(versions_))  // Found root or orphan.
      return EraseFrontOfBranch(itr);

    auto parents_child_itr(std::find_if(std::begin(parent_itr->second->children),
                                        std::end(parent_itr->second->children),
                                        [itr](VersionsItr child_itr) {
                                            return itr->first == child_itr->first;
                                        }));
    assert(parents_child_itr != std::end(parent_itr->second->children));
    versions_.erase(itr);
    if (!parent_itr->second->children.empty())  // Found fork.
      return;

    itr = parent_itr;
  }
}

void StructuredDataVersions::EraseFrontOfBranch(VersionsItr front_of_branch) {
  if (root_.second == front_of_branch) {  // Front of branch is 'root_'.
    if (orphans_.empty()) {
      versions_.erase(front_of_branch);
      root_ = std::make_pair(VersionName(), std::end(versions_));
      assert(versions_.empty() && tips_of_trees_.empty());
    } else {
      ReplaceRootFromOrphans();
    }
  } else {  // Front of branch is an orphan.
    auto orphan_itr(std::find_if(std::begin(orphans_),
                                 std::end(orphans_),
                                 [front_of_branch](const Orphans::value_type& orphan) {
                                   return orphan.second == front_of_branch;
                                 }));
    assert(orphan_itr != std::end(orphans_));
    orphans_.erase(orphan_itr);
    versions_.erase(front_of_branch);
  }
}

void StructuredDataVersions::clear() {
  versions_.clear();
  root_ = std::make_pair(VersionName(), std::end(versions_));
  tips_of_trees_.clear();
  orphans_.clear();
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
