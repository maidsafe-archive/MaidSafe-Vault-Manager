/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file licence.txt found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_ACTION_AUTHORITY_H_
#define MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_ACTION_AUTHORITY_H_

#include <map>
#include <memory>
#include <string>

#include "boost/filesystem/path.hpp"
#include "boost/signals2/signal.hpp"

#include "maidsafe/common/bounded_string.h"
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_actions/chunk_id.h"


namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace priv {

typedef crypto::TigerHash ChunkVersion;

namespace chunk_store { class ChunkStore; }

namespace chunk_actions {

namespace test {
class ChunkActionAuthorityTest;
class ChunkActionAuthorityTest_BEH_ValidStore_Test;
class ChunkActionAuthorityTest_BEH_ValidGet_Test;
class ChunkActionAuthorityTest_BEH_ValidDelete_Test;
class ChunkActionAuthorityTest_BEH_ValidModify_Test;
}  // namespace test


class ChunkActionAuthority {
 public:
  explicit ChunkActionAuthority(std::shared_ptr<chunk_store::ChunkStore> chunk_store);
  virtual ~ChunkActionAuthority();

  std::string Get(const ChunkId& name,
                  const ChunkVersion& version,
                  const asymm::PublicKey& public_key) const;
  // Retrieves a chunk's content as a file, potentially overwriting an existing file of the same
  // name.
  bool Get(const ChunkId& name,
           const fs::path& sink_file_name,
           const ChunkVersion& version,
           const asymm::PublicKey& public_key) const;
  bool Store(const ChunkId& name, const std::string& content, const asymm::PublicKey& public_key);
  bool Store(const ChunkId& name,
             const fs::path& source_file_name,
             bool delete_source_file,
             const asymm::PublicKey& public_key);
  // Returns true if chunk deleted or non-existant
  bool Delete(const ChunkId& name,
              const std::string& ownership_proof,
              const asymm::PublicKey& public_key);
  bool Modify(const ChunkId& name,
              const std::string& content,
              const asymm::PublicKey& public_key,
              int64_t* size_difference);
  bool Modify(const ChunkId& name,
              const fs::path& source_file_name,
              bool delete_source_file,
              const asymm::PublicKey& public_key,
              int64_t* size_difference);
  bool Has(const ChunkId& name,
           const ChunkVersion& version,
           const asymm::PublicKey& public_key) const;

  bool ValidName(const ChunkId& name) const;
  bool Cacheable(const ChunkId& name) const;
  bool Modifiable(const ChunkId& name) const;
  bool ModifyReplaces(const ChunkId& name) const;
  bool Payable(const ChunkId& name) const;
  bool ValidChunk(const ChunkId& name) const;
  ChunkVersion Version(const ChunkId& name) const;

  friend class test::ChunkActionAuthorityTest;
  friend class test::ChunkActionAuthorityTest_BEH_ValidStore_Test;
  friend class test::ChunkActionAuthorityTest_BEH_ValidGet_Test;
  friend class test::ChunkActionAuthorityTest_BEH_ValidDelete_Test;
  friend class test::ChunkActionAuthorityTest_BEH_ValidModify_Test;

 private:
  ChunkActionAuthority& operator=(const ChunkActionAuthority&);
  ChunkActionAuthority(const ChunkActionAuthority&);

  int ValidGet(const ChunkId& name,
               const ChunkVersion& version,
               const asymm::PublicKey& public_key,
               std::string* existing_content = nullptr) const;
  int ValidStore(const ChunkId& name,
                 const std::string& content,
                 const asymm::PublicKey& public_key) const;
  int ValidDelete(const ChunkId& name,
                  const std::string& ownership_proof,
                  const asymm::PublicKey& public_key) const;
  int ValidModify(const ChunkId& name,
                  const std::string& content,
                  const asymm::PublicKey& public_key,
                  int64_t* size_difference,
                  std::string* new_content = nullptr) const;
  virtual int ValidHas(const ChunkId& name,
                       const ChunkVersion& version,
                       const asymm::PublicKey& public_key) const;

  std::shared_ptr<chunk_store::ChunkStore> chunk_store_;
};

}  // namespace chunk_actions

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_ACTION_AUTHORITY_H_
