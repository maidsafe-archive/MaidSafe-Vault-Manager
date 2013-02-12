/* Copyright (c) 2012 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

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
