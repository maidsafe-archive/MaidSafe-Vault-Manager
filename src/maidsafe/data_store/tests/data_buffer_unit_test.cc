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

#include "maidsafe/data_store/data_buffer.h"

#include <utility>

#include "maidsafe/common/error.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/data_types/data_name_variant.h"

namespace fs = boost::filesystem;
namespace mpl = boost::mpl;

namespace maidsafe {
namespace data_store {

namespace test {

TEST_CASE("Zero size memory", "[Private][unit]") {
CHECK_NOTHROW(DataBuffer<std::string> buff(MemoryUsage(0), DiskUsage(100), nullptr));
}

TEST_CASE("Max memory usage must be <= max disk usage", "[Private][unit]") {
CHECK_THROWS_AS(DataBuffer<std::string> buff(MemoryUsage(1), DiskUsage(0), nullptr), std::exception);
}

TEST_CASE("Zero size disk and memory", "[Private][unit]") {
CHECK_NOTHROW(DataBuffer<std::string> buff(MemoryUsage(0), DiskUsage(0), nullptr));
}

TEST_CASE("Construct with complex key", "[Private][unit]") {
  typedef std::pair<std::string, std::string> key_type;
  CHECK_NOTHROW(DataBuffer<key_type> buff(MemoryUsage(0), DiskUsage(100), nullptr));
}

TEST_CASE("disk only insert and delete", "[Private][unit]") {
  DataBuffer<std::string> buff(MemoryUsage(0), DiskUsage(100), nullptr);
  CHECK_NOTHROW(buff.Store("a", NonEmptyString("b")));
  CHECK(NonEmptyString("b") == buff.Get("a"));
  CHECK_NOTHROW(buff.Delete("a"));
  CHECK_THROWS_AS(buff.Delete("a"), std::exception);
}

TEST_CASE("disk only insert and delete complex key", "[Private][unit]") {
  DataBuffer<std::pair<std::string, std::string>> buff(MemoryUsage(0), DiskUsage(100), nullptr);
  CHECK_NOTHROW(buff.Store(std::make_pair("a", "b"), NonEmptyString("b")));
  CHECK(NonEmptyString("b") == buff.Get(std::make_pair("a", "b")));
  CHECK_NOTHROW(buff.Delete(std::make_pair("a", "b")));
  CHECK_THROWS_AS(buff.Delete(std::make_pair("a", "b")), std::exception);
}

TEST_CASE("disk only insert and delete range", "[Private][unit]") {
  DataBuffer<std::pair<std::string, std::string>> buff(MemoryUsage(0), DiskUsage(100), nullptr);
  CHECK_NOTHROW(buff.Store(std::make_pair("a", "b"), NonEmptyString("b")));
  CHECK_NOTHROW(buff.Store(std::make_pair("b", "b"), NonEmptyString("b")));
  CHECK(NonEmptyString("b") == buff.Get(std::make_pair("a", "b")));
  std::string range("b");
  CHECK_NOTHROW(buff.DeleteRange(range));
  CHECK_THROWS_AS(buff.Delete(std::make_pair("a", "b")), std::exception);
  // CHECK_THROWS_AS(buff.Delete(predicate), std::exception);
}


}  // namespace test

}  // namespace data_store
}  // namespace maidsafe
