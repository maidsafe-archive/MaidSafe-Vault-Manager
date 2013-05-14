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
/*
         --14--           --15--
           |               |
           |               |
 --4--   --8--   --11--  --10--  --13--  --16--
   |       |       |     /         |      /
   |       |       |   /           |    /
 --3--   --7--   --9--           --12--
           |       |           /
           |       |         /
         --5--   --6--   --2--
            \      |     /
              \    |   /
                 --1--
                   |
                   |
                 --0--

The tree above represents the map of Versions with each number representing a different VersionName.
In the diagram, '0' is the first version (root) and has no parent (parent == end()), but is not an
orphan.

'0' is the parent of '1' and has a child count of 1.  '1' is the parent of '2', '5' and '6' and has
a child count of 3.

All versions other than the root ('0') without a parent are orphans.  There will always only be one
root.  If the current root is erased, a new root is chosen from the remaining versions.  This will
be the child of the deleted root, or if the entire branch containing the root was erased, an orphan
will be chosen at random.

The "tips of trees" are '4', '11', '13', '14', '15' and '16'.

*/

#ifndef MAIDSAFE_DATA_TYPES_STRUCTURED_DATA_VERSION_H_
#define MAIDSAFE_DATA_TYPES_STRUCTURED_DATA_VERSION_H_

#include <cstdint>
#include <map>
#include <utility>
#include <vector>

#include "maidsafe/common/types.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/data_types/immutable_data.h"


namespace maidsafe {

// All public functions in this class provide the strong exception guarantee.
class StructuredDataVersions {
 private:
  struct StructuredDataVersionsTag;

 public:
  typedef ImmutableData::name_type VersionName;
  typedef TaggedValue<NonEmptyString, StructuredDataVersionsTag> serialised_type;

  // Construct with a limit of 'max_versions' different versions and 'max_branches' different
  // branches (or "tips of trees").  Both must be >= 1 otherwise CommonErrors::invalid_parameter is
  // thrown.
  StructuredDataVersions(uint32_t max_versions, uint32_t max_branches);
  StructuredDataVersions(const StructuredDataVersions& other);
  StructuredDataVersions(StructuredDataVersions&& other);
  StructuredDataVersions& operator=(StructuredDataVersions other);
  friend void swap(StructuredDataVersions& lhs, StructuredDataVersions& rhs) MAIDSAFE_NOEXCEPT;
  StructuredDataVersions(const serialised_type& serialised_data_versions);
  serialised_type Serialise() const;

  // Inserts the 'new_version' into the map with 'old_version' as the parent.
  // • If 'old_version' doesn't exist, the version is added as an orphan.  For the root entry,
  //   'old_version' should be passed uninitialised.
  // • If adding the version causes 'max_versions_' to be exceeded, the root will be erased and its
  //   child assigned as the new root.  If the current root has >1 children,
  //   CommonErrors::unable_to_handle_request is thrown.
  // • If adding the version causes 'max_branches_' to be exceeded,
  //   CommonErrors::cannot_exceed_limit is thrown.
  // • If 'new_version' already exists but with a different 'old_version' parent,
  //   CommonErrors::invalid_parameter is thrown.
  void Put(const VersionName& old_version, const VersionName& new_version);
  // Returns all the "tips of trees" in unspecified order.
  std::vector<VersionName> Get() const;
  // Returns all the versions comprising a branch, index 0 being the tip, through to (including) the
  // root or the orphan at the start of that branch.  e.g., in the diagram above, GetBranch(11)
  // would return <11,9,6,1,0>.  GetBranch(15) would return <15,10,9,6,1,0>.
  // • If 'branch_tip' is not a "tip of tree" but does exist, CommonErrors::invalid_parameter is
  //   thrown.
  // • If 'branch_tip' doesn't exist, CommonErrors::no_such_element is thrown.
  std::vector<VersionName> GetBranch(const VersionName& branch_tip) const;
  // Similar to GetBranch except Versions are erased through to (excluding) the first version which
  // doesn't have exactly 1 child.  e.g. in the diagram above, DeleteBranchUntilFork(11) would erase
  // 11 only.  DeleteBranchUntilFork(15) would erase <15,10>.
  void DeleteBranchUntilFork(const VersionName& branch_tip);

  uint32_t max_versions() const { return max_versions_; }
  uint32_t max_branches() const { return max_branches_; }

  // TODO(Fraser#5#): 2013-05-14 - Do we need another GetBranch function which allows start point
  //                  other than TOT, and/or a max_count number of versions to return?  Similarly
  //                  DeleteBranch or Delete x from root upwards.  Maybe also LockBranch function to
  //                  disallow further versions being added while a client is attempting to resolve
  //                  conflicts?

 private:
  struct Details;
  typedef std::map<VersionName, Details> Versions;
  typedef Versions::value_type Version;
  typedef Versions::iterator VersionsItr;
  // The first value of the pair is the "old version" or parent ID which the orphan was added under.
  // The expectation is that the missing parent will soon be added, allowing the second value of the
  // pair to become "un-orphaned".
  typedef std::pair<VersionName, VersionsItr> Orphan;

  struct Details {
    Details();
    Details(const Details& other);
    Details(Details&& other);
    Details& operator=(Details other);

    VersionsItr parent;
    size_t child_count;
  };
  friend void swap(Details& lhs, Details& rhs) MAIDSAFE_NOEXCEPT;

  void Erase(VersionsItr itr);
  void InsertRoot(const VersionName& root_name);
  void InsertChild(const VersionName& child_name, VersionsItr parent_itr);
  void InsertOrphan(const VersionName& child_name);
  std::vector<Orphan>::iterator FindOrphanOf(const VersionName& name);
  std::vector<Orphan>::const_iterator FindOrphanOf(const VersionName& name) const;
  bool AtVersionsLimit() const;
  bool AtBranchesLimit() const;

  uint32_t max_versions_, max_branches_;
  Versions versions_;
  VersionsItr root_;
  std::vector<VersionsItr> tips_of_trees_;
  std::vector<Orphan> orphans_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_STRUCTURED_DATA_VERSION_H_
