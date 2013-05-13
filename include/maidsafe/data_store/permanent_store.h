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

#ifndef MAIDSAFE_DATA_STORE_PERMANENT_STORE_H_
#define MAIDSAFE_DATA_STORE_PERMANENT_STORE_H_

#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <utility>
#include <deque>
#include <set>
#include <vector>

#include "boost/filesystem/path.hpp"
#include "boost/variant.hpp"

#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/types.h"

#include "maidsafe/data_types/data_name_variant.h"


namespace maidsafe {

namespace data_store {

namespace test { class PermanentStoreTest; }

class PermanentStore {
 public:
  typedef DataNameVariant KeyType;

  PermanentStore(const boost::filesystem::path& disk_path, const DiskUsage& max_disk_usage);
  ~PermanentStore();

  void Put(const KeyType& key, const NonEmptyString& value);
  void Delete(const KeyType& key);
  NonEmptyString Get(const KeyType& key);

  // Return list of elements that should have but not exists yet
  std::vector<KeyType> ElementsToStore(std::set<KeyType> element_list);

  void SetMaxDiskUsage(DiskUsage max_disk_usage);

  DiskUsage GetMaxDiskUsage();
  DiskUsage GetCurrentDiskUsage();

  friend class test::PermanentStoreTest;

 private:
  PermanentStore(const PermanentStore&);
  PermanentStore& operator=(const PermanentStore&);

  boost::filesystem::path GetFilePath(const KeyType& key) const;
  bool HasDiskSpace(const uint64_t& required_space) const;
  boost::filesystem::path KeyToFilePath(const KeyType& key);

  const boost::filesystem::path kDiskPath_;
  DiskUsage max_disk_usage_, current_disk_usage_;
  const uint32_t kDepth_;
  std::mutex mutex_;
  GetIdentityVisitor get_identity_visitor_;
};

}  // namespace data_store

}  // namespace maidsafe


#endif  // MAIDSAFE_DATA_STORE_PERMANENT_STORE_H_
