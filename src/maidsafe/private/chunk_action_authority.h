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

#include <memory>
#include <string>
#include <vector>

#include "boost/signals2/signal.hpp"

#include "maidsafe/private/chunk_messages_pb.h"
#include "maidsafe/private/config.h"
#include "maidsafe/private/version.h"

#if MAIDSAFE_PRIVATE_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif

namespace bs2 = boost::signals2;


namespace maidsafe {

namespace priv {

unsigned char GetDataType(const std::string &name);



class ChunkActionAuthority {
 public:
  ChunkActionAuthority();
  ~ChunkActionAuthority();

  int ProcessData(const OperationType &op_type,
                  const std::string &name,
                  const std::string &data,
                  const asymm::PublicKey &public_key,
                  ChunkStorePtr chunk_store);

 private:
  ChunkActionAuthority &operator=(const ChunkActionAuthority&);
  ChunkActionAuthority(const ChunkActionAuthority&);

  void Init();

  int ProcessSignedData(const OperationType &op_type,
                        const std::string &name,
                        const std::string &data,
                        const asymm::PublicKey &public_key,
                        const bool &hashable,
                        ChunkStorePtr chunk_store);

  int PreOperationChecks(const OperationType &op_type,
                         const std::string &name,
                         const std::string &data,
                         const asymm::PublicKey &public_key,
                         const bool &hashable);

  int VerifyCurrentData(const std::string &name,
                        const asymm::PublicKey &public_key,
                        ChunkStorePtr chunk_store,
                        std::string *current_data);

  int ProcessMsidData(const OperationType &op_type,
                      const std::string &name,
                      const std::string &data,
                      const asymm::PublicKey &public_key,
                      ChunkStorePtr chunk_store);

  int ProcessMmidData(const OperationType &op_type,
                      const std::string &name,
                      const std::string &data,
                      const asymm::PublicKey &public_key,
                      ChunkStorePtr chunk_store);

  std::map<unsigned char, ProcessDataFunctor> rules_;
  bool initialised_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTION_AUTHORITY_H_
