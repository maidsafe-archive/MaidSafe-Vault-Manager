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

#ifndef MAIDSAFE_PRIVATE_CHUNK_ACTION_AUTHORITY_H_
#define MAIDSAFE_PRIVATE_CHUNK_ACTION_AUTHORITY_H_

#include <map>
#include <memory>
#include <string>

#include "boost/signals2/signal.hpp"

#include "maidsafe/common/chunk_action_authority.h"

#include "maidsafe/private/version.h"

#if MAIDSAFE_PRIVATE_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif

namespace bs2 = boost::signals2;


namespace maidsafe {

namespace priv {


class ChunkActionAuthority : public maidsafe::ChunkActionAuthority {
 public:
  ChunkActionAuthority() {}
  virtual ~ChunkActionAuthority() {}
  virtual int ValidOperation(const int &op_type,
                             const std::string &name,
                             const std::string &content,
                             const asymm::PublicKey &public_key,
                             std::shared_ptr<ChunkStore> chunk_store,
                             std::string *new_content = NULL) const;
  virtual int ValidOperation(const int &op_type,
                             const std::string &name,
                             const fs::path &path,
                             const asymm::PublicKey &public_key,
                             std::shared_ptr<ChunkStore> chunk_store,
                             std::string *new_content = NULL) const;
  virtual bool ValidName(const std::string &name) const;
  virtual bool Cacheable(const std::string &name) const;
  virtual bool ValidChunk(const std::string &name,
                          const std::string &content) const;
  virtual bool ValidChunk(const std::string &name,
                          const fs::path &path) const;
  virtual std::string Version(const std::string &name,
                              const std::string &content) const;
  virtual std::string Version(const std::string &name,
                              const fs::path &path) const;

 private:
  ChunkActionAuthority &operator=(const ChunkActionAuthority&);
  ChunkActionAuthority(const ChunkActionAuthority&);
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTION_AUTHORITY_H_
