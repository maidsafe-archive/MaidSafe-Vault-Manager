/*  Copyright 2013 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

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

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/log.h"
#include "maidsafe/common/types.h"

#include "maidsafe/data_types/data_name_variant.h"
#include "maidsafe/data_types/structured_data_versions.h"


namespace maidsafe {

namespace data_store {

class SureFileStore {
 public:
  typedef boost::future<std::vector<StructuredDataVersions::VersionName>> VersionNamesFuture;

  SureFileStore(const boost::filesystem::path& disk_path, DiskUsage max_disk_usage);
  ~SureFileStore();

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

  AsioService asio_service_;
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
  LOG(kVerbose) << "Getting: " << HexSubstr(data_name.value);
  auto promise(std::make_shared<boost::promise<Data>>());
  auto async_future(boost::async(boost::launch::async, [=] {
      try {
        auto result(this->DoGet(KeyType(data_name)));
        Data data(data_name, typename Data::serialised_type(result));
        LOG(kVerbose) << "Got: " << HexSubstr(data_name.value) << "  " << EncodeToHex(result);
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
  LOG(kVerbose) << "Putting: " << HexSubstr(data.name().value) << "  "
                << EncodeToHex(data.Serialise().data);
  asio_service_.service().post([this, data] {
    try {
      DoPut(KeyType(data.name()), data.Serialise());
    }
    catch(const std::exception& e) {
      LOG(kWarning) << "Put failed: " << e.what();
    }
  });
}

template<typename Data>
void SureFileStore::Delete(const typename Data::Name& data_name) {
  LOG(kVerbose) << "DELETING: " << HexSubstr(data_name.value);
  asio_service_.service().post([this, data_name] {
    try {
      DoDelete(KeyType(data_name));
    }
    catch(const std::exception& e) {
      LOG(kWarning) << "Delete failed: " << e.what();
    }
  });
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
