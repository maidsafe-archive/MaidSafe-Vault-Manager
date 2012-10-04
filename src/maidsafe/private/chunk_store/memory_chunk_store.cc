/***************************************************************************************************
 *  Copyright 2012 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/

#include "maidsafe/private/chunk_store/memory_chunk_store.h"

#include "maidsafe/common/utils.h"
#include "maidsafe/common/log.h"


namespace maidsafe {

namespace priv {

namespace chunk_store {

MemoryChunkStore::MemoryChunkStore() : ChunkStore(), chunks_() {}

MemoryChunkStore::~MemoryChunkStore() {}

std::string MemoryChunkStore::Get(const ChunkId& name) const {
  auto it = chunks_.find(name);
  if (it == chunks_.end()) {
    LOG(kError) << "Get - Can't get chunk " << Base32Substr(name);
    return "";
  }

  return (*it).second.second;
}

bool MemoryChunkStore::Get(const ChunkId& name, const fs::path& sink_file_name) const {
  auto it = chunks_.find(name);
  if (it == chunks_.end()) {
    LOG(kError) << "Get - Can't get chunk " << Base32Substr(name);
    return false;
  }

  return WriteFile(sink_file_name, (*it).second.second);
}

bool MemoryChunkStore::Store(const ChunkId& name, const std::string& content) {
  auto it(chunks_.lower_bound(name));
  if (it != chunks_.end() && (*it).first == name) {
    ++(*it).second.first;
//     LOG(kInfo) << "Store - Increased count of chunk " << Base32Substr(name)
//                << " to " << (*it).second.first;
    return true;
  }

  uintmax_t chunk_size(content.size());
  if (chunk_size == 0) {
    LOG(kError) << "Store - Empty contents passed for " << Base32Substr(name);
    return false;
  }

  if (!Vacant(chunk_size)) {
    LOG(kError) << "Store - Chunk " << Base32Substr(name) << " has size " << chunk_size
                << " > vacant space";
    return false;
  }

  if (!chunks_.empty()) {
    if (it == chunks_.begin())
      it = --chunks_.end();
    else
      --it;
  }
  chunks_.insert(it, std::make_pair(name, ChunkEntry(1, content)));
  IncreaseSize(chunk_size);
//   LOG(kInfo) << "Store - Stored chunk " << Base32Substr(name);
  return true;
}

bool MemoryChunkStore::Store(const ChunkId& name,
                             const fs::path& source_file_name,
                             bool delete_source_file) {
  boost::system::error_code ec;
  auto it = chunks_.find(name);
  if (it == chunks_.end()) {
    uintmax_t chunk_size(fs::file_size(source_file_name, ec));
    if (ec) {
      LOG(kError) << "Store - Failed to calculate size for chunk " << Base32Substr(name) << ": "
                  << ec.message();
      return false;
    }

    if (chunk_size == 0) {
      LOG(kError) << "Store - Chunk " << Base32Substr(name) << " has size 0";
      return false;
    }

    if (!Vacant(chunk_size)) {
      LOG(kError) << "Store - Chunk " << Base32Substr(name) << " has size " << chunk_size
                  << " > vacant space.";
      return false;
    }

    std::string content;
    if (!ReadFile(source_file_name, &content)) {
      LOG(kError) << "Store - Failed to read file for chunk " << Base32Substr(name);
      return false;
    }

    if (content.size() != chunk_size) {
      LOG(kError) << "Store - File content size " << content.size() << " != chunk_size "
                  << chunk_size << " for chunk " << Base32Substr(name);
      return false;
    }

    chunks_[name] = ChunkEntry(1, content);
    IncreaseSize(chunk_size);
//     LOG(kInfo) << "Store - Stored chunk " << Base32Substr(name);
  } else {
    //  chunk already exists - check valid path or empty path was passed in.
    boost::system::error_code ec;
    if (!source_file_name.empty() && (!fs::exists(source_file_name, ec) || ec)) {
      LOG(kError) << "Store - non-existent file passed: " << ec.message();
      return false;
    }

    ++(*it).second.first;
//     LOG(kInfo) << "Store - Increased count of chunk " << Base32Substr(name)
//                << " to " << (*it).second.first;
  }

  if (delete_source_file)
    fs::remove(source_file_name, ec);

  return true;
}

bool MemoryChunkStore::Delete(const ChunkId& name) {
  auto it = chunks_.find(name);
  if (it == chunks_.end()) {
//     LOG(kInfo) << "Delete - Chunk " << Base32Substr(name)
//                << " already deleted";
    return true;
  }

  if (--(*it).second.first == 0) {
    DecreaseSize((*it).second.second.size());
    chunks_.erase(it);
//     LOG(kInfo) << "Delete - Deleted chunk " << Base32Substr(name);
//   } else {
//     LOG(kInfo) << "Delete - Decreased count of chunk " << Base32Substr(name)
//                << " to " << (*it).second.first << " via deletion";
  }

  return true;
}

bool MemoryChunkStore::Modify(const ChunkId& name, const std::string& content) {
  auto it = chunks_.find(name);
  if (it == chunks_.end())
    return false;

  std::string current_content((*it).second.second);

  uintmax_t content_size_difference;
  bool increase_size(false);
  if (!AssessSpaceRequirement(current_content.size(), content.size(), &increase_size,
                              &content_size_difference)) {
    LOG(kError) << "Size differential unacceptable - increase_size: " << increase_size << ", name: "
                << Base32Substr(name);
    return false;
  }

  chunks_[name] = ChunkEntry((*it).second.first, content);

  AdjustChunkStoreStats(content_size_difference, increase_size);
  return true;
}

bool MemoryChunkStore::Modify(const ChunkId& name,
                              const fs::path& source_file_name,
                              bool delete_source_file) {
  if (source_file_name.empty()) {
    LOG(kError) << "source_file_name empty: " << Base32Substr(name);
    return false;
  }

  std::string content;
  if (!ReadFile(source_file_name, &content)) {
    LOG(kError) << "Error reading file: " << Base32Substr(name) << ", path: " << source_file_name;
    return false;
  }

  if (!Modify(name, content)) {
    LOG(kError) << "Failed to modify: " << Base32Substr(name);
    return false;
  }

  boost::system::error_code ec;
  if (delete_source_file)
    fs::remove(source_file_name, ec);
  return true;
}

bool MemoryChunkStore::Has(const ChunkId& name) const {
  bool found(chunks_.find(name) != chunks_.end());
//   LOG(kInfo) << (found ? "Have chunk " : "Do not have chunk ")
//              << Base32Substr(name);
  return found;
}

bool MemoryChunkStore::MoveTo(const ChunkId& name, ChunkStore* sink_chunk_store) {
  if (!sink_chunk_store) {
    LOG(kError) << "MoveTo - NULL sink passed for chunk " << Base32Substr(name);
    return false;
  }

  auto it = chunks_.find(name);
  if (it == chunks_.end()) {
    LOG(kWarning) << "MoveTo - Failed to find chunk " << Base32Substr(name);
    return false;
  }

  if (!sink_chunk_store->Store(name, (*it).second.second)) {
    LOG(kError) << "MoveTo - Failed to store chunk " << Base32Substr(name) << " in sink";
    return false;
  }

  if (--(*it).second.first == 0) {
    DecreaseSize((*it).second.second.size());
    chunks_.erase(it);
    LOG(kInfo) << "MoveTo - Moved chunk " << Base32Substr(name);
  } else {
    LOG(kInfo) << "MoveTo - Decreased count of chunk " << Base32Substr(name) << " to "
               << (*it).second.first << " via move";
  }

  return true;
}

uintmax_t MemoryChunkStore::Size(const ChunkId& name) const {
  auto it = chunks_.find(name);
  if (it == chunks_.end()) {
    LOG(kError) << "Chunk not found: " << Base32Substr(name);
    return 0;
  }

  return (*it).second.second.size();
}

uintmax_t MemoryChunkStore::Count(const ChunkId& name) const {
  auto it = chunks_.find(name);
  if (it == chunks_.end()) {
    LOG(kError) << "Chunk not found: " << Base32Substr(name);
    return 0;
  }

  return (*it).second.first;
}

uintmax_t MemoryChunkStore::Count() const {
  return chunks_.size();
}

bool MemoryChunkStore::Empty() const {
  return chunks_.empty();
}

void MemoryChunkStore::Clear() {
  chunks_.clear();
  ChunkStore::Clear();
}

std::vector<ChunkData> MemoryChunkStore::GetChunks() const {
  std::vector<ChunkData> chunk_list;

  for (auto it = chunks_.begin(); it != chunks_.end(); ++it) {
    ChunkData chunk_data(it->first, Size(it->first));
    chunk_list.push_back(chunk_data);
  }

  return chunk_list;
}

}  // namespace chunk_store

}  // namespace priv

}  // namespace maidsafe
