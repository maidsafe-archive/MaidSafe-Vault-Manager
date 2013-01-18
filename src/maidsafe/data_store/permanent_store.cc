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

#include "maidsafe/data_store/permanent_store.h"

#include <string>

#include "boost/filesystem/convenience.hpp"
#include "boost/lexical_cast.hpp"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"

namespace maidsafe {

namespace data_store {

namespace {

void InitialiseDiskRoot(const fs::path& disk_root) {
  boost::system::error_code error_code;
  if (!fs::exists(disk_root, error_code)) {
    if (!fs::create_directories(disk_root, error_code)) {
      LOG(kError) << "Can't create disk root at " << disk_root << ": " << error_code.message();
      ThrowError(CommonErrors::uninitialised);
      return;
    }
  }
  // Check disk_root is writable...
  fs::path test_file(disk_root / "TestFile");
  if (!WriteFile(test_file, "Test")) {
    LOG(kError) << "Can't write file " << test_file;
    ThrowError(CommonErrors::uninitialised);
    return;
  }
  fs::remove(test_file);
}

}  // unnamed namespace

PermanentStore::PermanentStore(const fs::path& disk_path, const DiskUsage& max_disk_usage)
    : kDiskPath_(disk_path),
      max_disk_usage_(max_disk_usage),
      current_disk_usage_(0),
      kDepth_(5),
      get_identity_(),
      get_tag_() {
  InitialiseDiskRoot(kDiskPath_);
  try {
    fs::directory_iterator it(kDiskPath_), end;
    for (; it != end; ++it) {
      boost::system::error_code error_code;
      uint64_t file_size(fs::file_size(*it, error_code));
      if (error_code) {
        LOG(kError) << "Error getting file size of " << *it << ": " << error_code.message();
        ThrowError(CommonErrors::filesystem_io_error);
      }
      current_disk_usage_.data += file_size;
    }
    if (current_disk_usage_ > max_disk_usage_)
      ThrowError(CommonErrors::cannot_exceed_max_disk_usage);
  }
  catch(const std::exception& exception) {
    LOG(kError) << exception.what();
    ThrowError(CommonErrors::invalid_parameter);
  }
}

PermanentStore::~PermanentStore() {}

void PermanentStore::Put(const KeyType& key, const NonEmptyString& value) {
  std::unique_lock<std::mutex> lock(mutex_);
  if (!HasDiskSpace(value.string().size())) {
    LOG(kError) << "Cannot store "
                << HexSubstr(boost::apply_visitor(get_identity_, key).string()) << " since its "
                << value.string().size() << " bytes exceeds max of " << max_disk_usage_
                << " bytes.";
    ThrowError(CommonErrors::cannot_exceed_max_disk_usage);
  }
  if (!WriteFile(KeyToFilePath(key), value.string())) {
    LOG(kError) << "Failed to write "
                << HexSubstr(boost::apply_visitor(get_identity_, key).string()) << " to disk.";
    ThrowError(CommonErrors::filesystem_io_error);
  }
  current_disk_usage_.data += value.string().size();
}

void PermanentStore::Delete(const KeyType& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  fs::path path(KeyToFilePath(key));
  boost::system::error_code error_code;
  uint64_t file_size(fs::file_size(path, error_code));
  if (error_code) {
    LOG(kError) << "Error getting file size of " << path << ": " << error_code.message();
    ThrowError(CommonErrors::filesystem_io_error);
  }
  if (!fs::remove(path, error_code) || error_code) {
    LOG(kError) << "Error removing " << path << ": " << error_code.message();
    ThrowError(CommonErrors::filesystem_io_error);
  }
  current_disk_usage_.data -= file_size;
}

NonEmptyString PermanentStore::Get(const KeyType& key) {
  std::lock_guard<std::mutex> lock(mutex_);
  return ReadFile(KeyToFilePath(key));
}

void PermanentStore::SetMaxDiskUsage(DiskUsage max_disk_usage) {
  if (current_disk_usage_ > max_disk_usage)
    ThrowError(CommonErrors::invalid_parameter);
  max_disk_usage_ = max_disk_usage;
}

fs::path PermanentStore::GetFilePath(const KeyType& key) {
  return kDiskPath_ / (EncodeToBase32(boost::apply_visitor(get_identity_, key))
        + boost::lexical_cast<std::string>(static_cast<int>(boost::apply_visitor(get_tag_, key))));
}

bool PermanentStore::HasDiskSpace(const uint64_t& required_space) const {
  return current_disk_usage_ + required_space <= max_disk_usage_;
}

fs::path PermanentStore::KeyToFilePath(const KeyType& key) {
  Identity file_name(EncodeToBase32(GetFilePath(key).filename().string()));

  uint32_t directory_depth = kDepth_;
  if (file_name.string().length() < directory_depth)
    directory_depth = file_name.string().length() - 1;

  fs::path disk_path(kDiskPath_);
  for (uint32_t i = 0; i < directory_depth; ++i)
    disk_path /= file_name.string().substr(i, 1);

  boost::system::error_code ec;
  fs::create_directories(disk_path, ec);

  return fs::path(disk_path / file_name.string().substr(directory_depth));
}

}  // namespace data_store

}  // namespace maidsafe
