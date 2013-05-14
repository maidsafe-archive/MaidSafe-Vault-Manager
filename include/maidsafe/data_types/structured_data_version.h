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
 --4--   --8--   --11--  --10--  --13--
   |       |       |     /         |
   |       |       |   /           |
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

The tree above represents the set of Versions with each number representing a different VersionName.
In the diagram, '0' is the first version, has no parent (parent == end()), but is not an orphan.
'0' is the parent of '1' and has a child count of 1.  '1' is the parent of '2', '5' and '6' and has
a child count of 3.

All versions other than the first one ('0') without a parent are orphans.

The "tips of trees" are '4', '11', '13', '14' and '15'.

*/

#ifndef MAIDSAFE_DATA_TYPES_STRUCTURED_DATA_VERSION_H_
#define MAIDSAFE_DATA_TYPES_STRUCTURED_DATA_VERSION_H_

#include <cstdint>
#include <set>
#include <utility>
#include <vector>

#include "maidsafe/common/types.h"
#include "maidsafe/common/tagged_value.h"

#include "maidsafe/data_types/immutable_data.h"


namespace maidsafe {

class StructuredDataVersions {
 private:
  struct StructuredDataVersionsTag;

 public:
  typedef ImmutableData::name_type VersionName;
  typedef TaggedValue<NonEmptyString, StructuredDataVersionsTag> serialised_type;

  // Construct with a limit of 'max_versions' different versions and 'max_branches' different
  // branches (or "tips of trees").
  StructuredDataVersions(uint32_t max_versions, uint32_t max_branches);
  StructuredDataVersions(const StructuredDataVersions& other);
  StructuredDataVersions(StructuredDataVersions&& other);
  StructuredDataVersions& operator=(StructuredDataVersions other);
  friend void swap(StructuredDataVersions& lhs, StructuredDataVersions& rhs) MAIDSAFE_NOEXCEPT;
  StructuredDataVersions(const serialised_type& serialised_data_versions);
  serialised_type Serialise() const;

  // Inserts the 'new_version' into the set with 'old_version' as the parent.  If 'old_version'
  // doesn't exist, the version is added as an orphan.  For the first entry (i.e. versions_.empty())
  // 'old_version' should be uninitialised.  If adding the version causes 'max_versions_' or 'max_branches_' to be exceeded, ...
  void Put(const VersionName& old_version, const VersionName& new_version);
  // Returns all the "tips of trees" in unspecified order.
  std::vector<VersionName> Get() const;
  // Returns all the versions comprising a branch, index 0 being the tip, through to (including) the
  // first version which doesn't have exactly 1 child.  E.g., in the diagram above, GetBranch(11)
  // would return <11,9>.  GetBranch(15) would return <15,10,9>.  If 'branch_tip' is not a "tip of
  // tree" but does exist, CommonErrors::invalid_parameter is thrown.  If 'branch_tip' doesn't
  // exist, CommonErrors::no_such_element is thrown.
  std::vector<VersionName> GetBranch(const VersionName& branch_tip) const;
  // Similar to GetBranch except Versions are erased.
  void DeleteBranch(const VersionName& branch_tip);

  uint32_t max_versions() const { return max_versions_; }
  uint32_t max_branches() const { return max_branches_; }

  // TODO(Fraser#5#): 2013-05-14 - Do we need another GetBranch function which allows start point
  //                  other than TOT, and/or a max_count number of versions to return?  Similarly
  //                  DeleteBranch or Delete x from root upwards.  Maybe also LockBranch function to
  //                  disallow further versions being added while a client is attempting to resolve
  //                  conflicts?

 private:
  struct Version;
  typedef std::set<Version> Versions;
  typedef Versions::iterator VersionsItr;

  struct Version {
    explicit Version(const VersionName& name_in);
    Version(const Version& other);
    Version(Version&& other);
    Version& operator=(Version other);

    VersionName name;
    VersionsItr parent;
    size_t child_count;
  };
  friend void swap(Version& lhs, Version& rhs) MAIDSAFE_NOEXCEPT;
  friend bool operator<(const Version& lhs, const Version& rhs);

  void Validate() const;

  uint32_t max_versions_, max_branches_;
  std::set<Version> versions_;
  VersionsItr root_;
  std::vector<VersionsItr> tips_of_trees_;
  // The first value of the pair is the "old version" or parent ID which the orphan was added under.
  // The expectation is that the missing parent will soon be added, allowing the second value of the
  // pair to become "un-orphaned".
  std::vector<std::pair<VersionName, VersionsItr>> orphans_;
};

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_TYPES_STRUCTURED_DATA_VERSION_H_
