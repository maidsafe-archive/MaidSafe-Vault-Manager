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

#include <atomic>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <future>
#include <map>
#include <mutex>
#include <utility>
#include <deque>

#include "boost/filesystem/path.hpp"
#include "boost/variant.hpp"

#include "maidsafe/common/tagged_value.h"
#include "maidsafe/common/types.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/data_types/immutable_data.h"
#include "maidsafe/data_types/mutable_data.h"

namespace fs = boost::filesystem;

namespace maidsafe {

namespace data_store {

namespace test { class PermanentStoreTest; }

class PermanentStore {
 public:
  typedef boost::variant<passport::PublicAnmid::name_type,
                         passport::PublicAnsmid::name_type,
                         passport::PublicAntmid::name_type,
                         passport::PublicAnmaid::name_type,
                         passport::PublicMaid::name_type,
                         passport::PublicPmid::name_type,
                         passport::Mid::name_type,
                         passport::Smid::name_type,
                         passport::Tmid::name_type,
                         passport::PublicAnmpid::name_type,
                         passport::PublicMpid::name_type,
                         ImmutableData::name_type,
                         MutableData::name_type> KeyType;

  PermanentStore(const fs::path& disk_path, const DiskUsage& max_disk_usage);
  ~PermanentStore();

  void Put(const KeyType& key, const NonEmptyString& value);
  void Delete(const KeyType& key);
  NonEmptyString Get(const KeyType& key);

  void SetMaxDiskUsage(DiskUsage max_disk_usage);

  friend class test::PermanentStoreTest;

 private:
  PermanentStore(const PermanentStore&);
  PermanentStore& operator=(const PermanentStore&);

  struct GetIdentity : public boost::static_visitor<Identity>
  {
     template<typename T, typename Tag>
     Identity operator()(const TaggedValue<T, Tag>& t)
     {
        return t.data;
     }
  };

  struct GetTag : public boost::static_visitor<detail::DataTagValue>
  {
     template<typename T, typename Tag>
     detail::DataTagValue operator()(const TaggedValue<T, Tag>&)
     {
        return TaggedValue<T, Tag>::tag_type::kEnumValue;
     }
  };

  fs::path GetFilePath(const KeyType& key);
  bool HasDiskSpace(const uint64_t& required_space) const;
  fs::path KeyToFilePath(const KeyType& key);

  const fs::path kDiskPath_;
  DiskUsage max_disk_usage_, current_disk_usage_;
  const uint32_t kDepth_;
  std::mutex mutex_;
  GetIdentity get_identity_;
  GetTag get_tag_;
};

}  // namespace data_store

}  // namespace maidsafe


#endif  // MAIDSAFE_DATA_STORE_PERMANENT_STORE_H_
