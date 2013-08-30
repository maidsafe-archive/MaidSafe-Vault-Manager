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

#ifndef MAIDSAFE_DATA_STORE_SURE_FILE_STORE_H_
#define MAIDSAFE_DATA_STORE_SURE_FILE_STORE_H_

#include <cstdint>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include "boost/filesystem/path.hpp"
#ifdef _MSC_VER
#  pragma warning(push)
#  pragma warning(disable: 4702)
#endif
#include "boost/thread/future.hpp"
#ifdef _MSC_VER
#  pragma warning(pop)
#endif

#include "maidsafe/common/log.h"
#include "maidsafe/common/types.h"

#include "maidsafe/data_types/data_name_variant.h"
#include "maidsafe/data_types/structured_data_versions.h"


namespace maidsafe {

namespace data_store {

class SureFileStore {
 public:
  typedef boost::future<std::vector<StructuredDataVersions::VersionName>> VersionNamesFuture;

  SureFileStore(const boost::filesystem::path& disk_path, const DiskUsage& max_disk_usage);

  template<typename Data>
  boost::future<Data> Get(
      const typename Data::Name& data_name,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  template<typename Data>
  void Put(const Data& data);

  template<typename Data>
  void Delete(const typename Data::Name& data_name);

  template<typename Data>
  VersionNamesFuture GetVersions(
      const typename Data::Name& data_name,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  template<typename Data>
  VersionNamesFuture GetBranch(
      const typename Data::Name& data_name,
      const StructuredDataVersions::VersionName& branch_tip,
      const std::chrono::steady_clock::duration& timeout = std::chrono::seconds(10));

  template<typename Data>
  void PutVersion(const typename Data::Name& data_name,
                  const StructuredDataVersions::VersionName& old_version_name,
                  const StructuredDataVersions::VersionName& new_version_name);

  template<typename Data>
  void DeleteBranchUntilFork(const typename Data::Name& data_name,
                             const StructuredDataVersions::VersionName& branch_tip);

  void SetMaxDiskUsage(DiskUsage max_disk_usage);

  DiskUsage GetMaxDiskUsage() const;
  DiskUsage GetCurrentDiskUsage() const;

 private:
  typedef DataNameVariant KeyType;
  typedef boost::promise<std::vector<StructuredDataVersions::VersionName>> VersionNamesPromise;

  SureFileStore(const SureFileStore&);
  SureFileStore(SureFileStore&&);
  SureFileStore& operator=(SureFileStore);

  NonEmptyString DoGet(const KeyType& key) const;
  void DoPut(const KeyType& key, const NonEmptyString& value);
  void DoDelete(const KeyType& key);

  boost::filesystem::path GetFilePath(const KeyType& key) const;
  bool HasDiskSpace(const uint64_t& required_space) const;
  boost::filesystem::path KeyToFilePath(const KeyType& key, bool create_if_missing) const;
  uint32_t GetReferenceCount(const boost::filesystem::path& path) const;
  void Write(const boost::filesystem::path& path,
             const NonEmptyString& value,
             const uintmax_t& size);
  uintmax_t Remove(const boost::filesystem::path& path);
  uintmax_t Rename(const boost::filesystem::path& old_path,
                   const boost::filesystem::path& new_path);

  std::unique_ptr<StructuredDataVersions> ReadVersions(const KeyType& key) const;
  void WriteVersions(const KeyType& key, const StructuredDataVersions& versions);

  const boost::filesystem::path kDiskPath_;
  DiskUsage max_disk_usage_, current_disk_usage_;
  const uint32_t kDepth_;
  mutable std::mutex mutex_;
  GetIdentityVisitor get_identity_visitor_;
};



// ==================== Implementation =============================================================
template<typename Data>
boost::future<Data> SureFileStore::Get(const typename Data::Name& data_name,
                                       const std::chrono::steady_clock::duration& /*timeout*/) {
  auto promise(std::make_shared<boost::promise<Data>>());
  auto async_future(boost::async(boost::launch::async, [=] {
      try {
        auto result(this->DoGet(KeyType(data_name)));
        Data data(data_name, typename Data::serialised_type(result));
        promise->set_value(data);
      }
      catch(const std::exception& e) {
        LOG(kError) << e.what();
        promise->set_exception(boost::current_exception());
      }
  }));
  static_cast<void>(async_future);
  return promise->get_future();
}

template<typename Data>
void SureFileStore::Put(const Data& data) {
  DoPut(KeyType(data.name()), data.data());
}

template<typename Data>
void SureFileStore::Delete(const typename Data::Name& data_name) {
  DoDelete(KeyType(data_name));
}

template<typename Data>
SureFileStore::VersionNamesFuture SureFileStore::GetVersions(
    const typename Data::Name& data_name,
    const std::chrono::steady_clock::duration& /*timeout*/) {
  auto promise(std::make_shared<VersionNamesPromise>());
  auto async_future(boost::async(boost::launch::async, [=] {
      try {
        KeyType key(data_name);
        std::lock_guard<std::mutex> lock(this->mutex_);
        auto versions(this->ReadVersions(key));
        if (!versions)
          ThrowError(CommonErrors::no_such_element);
        promise->set_value(versions->Get());
      }
      catch(const std::exception& e) {
        LOG(kError) << e.what();
        promise->set_exception(boost::current_exception());
      }
  }));
  static_cast<void>(async_future);
  return promise->get_future();
}

template<typename Data>
SureFileStore::VersionNamesFuture SureFileStore::GetBranch(
    const typename Data::Name& data_name,
    const StructuredDataVersions::VersionName& branch_tip,
    const std::chrono::steady_clock::duration& /*timeout*/) {
  auto promise(std::make_shared<VersionNamesPromise>());
  auto async_future(boost::async(boost::launch::async, [=] {
      try {
        KeyType key(data_name);
        std::lock_guard<std::mutex> lock(this->mutex_);
        auto versions(this->ReadVersions(key));
        if (!versions)
          ThrowError(CommonErrors::no_such_element);
        promise->set_value(versions->GetBranch(branch_tip));
      }
      catch(const std::exception& e) {
        LOG(kError) << e.what();
        promise->set_exception(boost::current_exception());
      }
  }));
  static_cast<void>(async_future);
  return promise->get_future();
}

template<typename Data>
void SureFileStore::PutVersion(const typename Data::Name& data_name,
                               const StructuredDataVersions::VersionName& old_version_name,
                               const StructuredDataVersions::VersionName& new_version_name) {
  try {
    KeyType key(data_name);
    std::lock_guard<std::mutex> lock(mutex_);
    auto versions(ReadVersions(key));
    if (!versions)
      versions.reset(new StructuredDataVersions(100, 5));
    versions->Put(old_version_name, new_version_name);
    WriteVersions(key, *versions);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
  }
}

template<typename Data>
void SureFileStore::DeleteBranchUntilFork(const typename Data::Name& data_name,
                                          const StructuredDataVersions::VersionName& branch_tip) {
  try {
    KeyType key(data_name);
    std::lock_guard<std::mutex> lock(mutex_);
    auto versions(ReadVersions(key));
    if (!versions)
      ThrowError(CommonErrors::no_such_element);
    versions->DeleteBranchUntilFork(branch_tip);
    WriteVersions(key, *versions);
  }
  catch(const std::exception& e) {
    LOG(kError) << e.what();
  }
}

}  // namespace data_store

}  // namespace maidsafe

#endif  // MAIDSAFE_DATA_STORE_SURE_FILE_STORE_H_
