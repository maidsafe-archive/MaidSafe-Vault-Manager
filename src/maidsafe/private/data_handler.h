/*
* ============================================================================
*
* Copyright [2011] maidsafe.net limited
*
* Created:      2011-10-27
* Author:       Team
* Company:      maidsafe.net limited
*
* The following source code is property of maidsafe.net limited and is not
* meant for external use.  The use of this code is governed by the license
* file LICENSE.TXT found in the root of this directory and also on
* www.maidsafe.net.
*
* You are not free to copy, amend or otherwise use this source code without
* the explicit written permission of the board of directors of maidsafe.net.
*
* ============================================================================
*/

#ifndef MAIDSAFE_LIFESTUFF_DATA_HANDLER_H_
#define MAIDSAFE_LIFESTUFF_DATA_HANDLER_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/signals2/signal.hpp"

#include "maidsafe/common/rsa.h"

namespace bs2 = boost::signals2;

namespace maidsafe {

class ChunkStore;

enum DataType {
  kUnknown = -1,
  kHashableSigned,
  kNonHashableSigned,
  kAnmpid,
  kMpid,
  kMsid,
  kMmid
};

namespace lifestuff {

class DataWrapper;

class DataHandler {
 public:
  enum OperationType { kStore, kDelete, kUpdate, kGet, kHas };
  typedef std::shared_ptr<bs2::signal<void(const std::string&)>>
          GetStringSignalPtr;
  typedef std::shared_ptr<bs2::signal<void(const std::vector<std::string>&)>>
          GetVectorSignalPtr;

  DataHandler();
  ~DataHandler();

  GetStringSignalPtr get_string_signal() const;
  GetVectorSignalPtr get_vector_signal() const;

  int ProcessData(const OperationType &op_type,
                  const std::string &name,
                  const std::string &data,
                  const asymm::PublicKey &public_key,
                  std::shared_ptr<ChunkStore> chunk_store);

 private:
  DataHandler &operator=(const DataHandler&);
  DataHandler(const DataHandler&);

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

}  // namespace lifestuff

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_DATA_HANDLER_H_
