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

#include "maidsafe/common/rsa.h"

#include "maidsafe/private/chunk_messages_pb.h"
#include "maidsafe/private/version.h"

#if MAIDSAFE_PRIVATE_VERSION != 100
#  error This API is not compatible with the installed library.\
    Please update the library.
#endif

namespace bs2 = boost::signals2;


namespace maidsafe {

class ChunkStore;


namespace priv {

enum DataType {
  kUnknown = -1,
  kHashableSigned,
  kNonHashableSigned,
  kAnmpid,
  kMpid,
  kMsid,
  kMmid,
  kMaxDataType  // This enumeration must always be last
};

class DataWrapper;

DataType GetDataTypeFromName(const std::string &name);



class ChunkActionAuthority {
 public:
  enum OperationType { kStore, kDelete, kUpdate, kGet, kHas };
  typedef std::shared_ptr<bs2::signal<void(const std::string&)>>
          GetStringSignalPtr;
  typedef std::shared_ptr<bs2::signal<void(const std::vector<std::string>&)>>
          GetVectorSignalPtr;

  ChunkActionAuthority();
  ~ChunkActionAuthority();

  GetStringSignalPtr get_string_signal() const;
  GetVectorSignalPtr get_vector_signal() const;

  int ProcessData(const OperationType &op_type,
                  const std::string &name,
                  const std::string &data,
                  const asymm::PublicKey &public_key,
                  std::shared_ptr<ChunkStore> chunk_store);

 private:
  ChunkActionAuthority &operator=(const ChunkActionAuthority&);
  ChunkActionAuthority(const ChunkActionAuthority&);

  int ProcessSignedData(const OperationType &op_type,
                        const std::string &name,
                        const DataWrapper &data,
                        const asymm::PublicKey &public_key,
                        const bool &hashable,
                        std::shared_ptr<ChunkStore> chunk_store);

  int PreOperationChecks(const OperationType &op_type,
                         const std::string &name,
                         const DataWrapper &data_wrapper,
                         const asymm::PublicKey &public_key,
                         const bool &hashable);

  int VerifyCurrentData(const std::string &name,
                        const asymm::PublicKey &public_key,
                        std::shared_ptr<ChunkStore> chunk_store,
                        std::string *current_data);

  int ProcessMsidData(const OperationType &op_type,
                      const std::string &name,
                      const DataWrapper &data,
                      const asymm::PublicKey &public_key,
                      std::shared_ptr<ChunkStore> chunk_store);

  int ProcessMmidData(const OperationType &op_type,
                      const std::string &name,
                      const DataWrapper &data,
                      const asymm::PublicKey &public_key,
                      std::shared_ptr<ChunkStore> chunk_store);

  DataType GetDataType(const std::string &name,
                       std::shared_ptr<ChunkStore> chunk_store) const;

  GetStringSignalPtr get_string_signal_;
  GetVectorSignalPtr get_vector_signal_;
};

}  // namespace priv

}  // namespace maidsafe

#endif  // MAIDSAFE_PRIVATE_CHUNK_ACTION_AUTHORITY_H_
