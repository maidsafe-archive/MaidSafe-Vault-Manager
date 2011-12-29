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

namespace chunk_actions {

std::string ApplyTypeToName(const std::string &name, unsigned char chunk_type);
std::string RemoveTypeFromName(const std::string &name);
unsigned char GetDataType(const std::string &name);

}  // namespace chunk_actions


class ChunkActionAuthority : public maidsafe::ChunkActionAuthority {
 public:
  explicit ChunkActionAuthority(std::shared_ptr<ChunkStore> chunk_store)
      : maidsafe::ChunkActionAuthority(chunk_store) {}
  virtual ~ChunkActionAuthority() {}
  // Delete is as per base class Delete except for SignaturePackets, which are
  // replaced with invalid content to avoid them being renewed by a different
  // owner
  virtual bool Delete(const std::string &name,
                      const std::string &version,
                      const std::string &ownership_proof,
                      const asymm::PublicKey &public_key);
  virtual bool ValidName(const std::string &name) const;
  virtual bool Cacheable(const std::string &name) const;
  virtual bool ValidChunk(const std::string &name) const;
  virtual std::string Version(const std::string &name) const;

 protected:
  virtual int ValidGet(const std::string &name,
                       const std::string &version,
                       const asymm::PublicKey &public_key,
                       std::string *existing_content = NULL) const;
  virtual int ValidStore(const std::string &name,
                         const std::string &content,
                         const asymm::PublicKey &public_key) const;
  virtual int ValidDelete(const std::string &name,
                          const std::string &version,
                          const std::string &ownership_proof,
                          const asymm::PublicKey &public_key) const;
  virtual int ValidModify(const std::string &name,
                          const std::string &content,
                          const std::string &version,
                          const asymm::PublicKey &public_key,
                          std::string *new_content = NULL) const;
  virtual int ValidHas(const std::string &name,
                       const std::string &version,
                       const asymm::PublicKey &public_key) const;

 private:
  ChunkActionAuthority &operator=(const ChunkActionAuthority&);
  ChunkActionAuthority(const ChunkActionAuthority&);
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTIONS_CHUNK_ACTION_AUTHORITY_H_
