/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

#ifndef MAIDSAFE_LIFESTUFF_MANAGER_RETURN_CODES_H_
#define MAIDSAFE_LIFESTUFF_MANAGER_RETURN_CODES_H_

namespace maidsafe {

enum ReturnCode {
  kSuccess = 0,

  // Download Manager
  kUninitialised = -250001,
  kManifestFailure = -250002,
  kDownloadFailure = -250003,
  kNoVersionChange = -250004,
  kLocalFailure = -250005,

  // Transport
  kAlreadyStarted = -350001,
  kInvalidAddress = -350002,
  kSetOptionFailure = -350003,
  kBindError = -350004,
  kListenError = -350005,
  kMessageSizeTooLarge = -350006,
  kReceiveFailure = -350007,
  kReceiveTimeout = -350008,
  kSendFailure = -350009,
  kSendTimeout = -350010,
  kConnectFailure = -350011
};

}  // namespace maidsafe

#endif  // MAIDSAFE_LIFESTUFF_MANAGER_RETURN_CODES_H_
