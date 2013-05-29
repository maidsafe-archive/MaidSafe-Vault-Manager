/***************************************************************************************************
 *  Copyright 2013 maidsafe.net limited                                                            *
 *                                                                                                 *
 *  The following source code is property of MaidSafe.net limited and is not meant for external    *
 *  use. The use of this code is governed by the licence file licence.txt found in the root of     *
 *  this directory and also on www.maidsafe.net.                                                   *
 *                                                                                                 *
 *  You are not free to copy, amend or otherwise use this source code without the explicit written *
 *  permission of the board of directors of MaidSafe.net.                                          *
 **************************************************************************************************/


#include <string>

#include "maidsafe/common/test.h"
#include "maidsafe/common/utils.h"

#include "maidsafe/data_types/structured_data_versions.h"


namespace maidsafe {

namespace test {

namespace {

typedef StructuredDataVersions::VersionName VersionName;

ImmutableData::name_type RandomId() {
  return ImmutableData::name_type(Identity(RandomAlphaNumericString(64)));
}

std::vector<VersionName> AddBranch(StructuredDataVersions& versions,
                                   VersionName old_version,
                                   uint32_t start_index,
                                   uint32_t count) {
  std::vector<VersionName> branch(1, old_version);
  for (uint32_t i(0); i != count; ++i) {
    VersionName new_version(start_index + i, RandomId());
    versions.Put(old_version, new_version);
    branch.push_back(new_version);
    old_version = new_version;
  }
  return branch;
}

void ConstructAsDiagram(StructuredDataVersions& versions) {
/*   7-yyy       0-aaa
       |           |
       |           |
     8-zzz       1-bbb
              /    |   \
            /      |     \
         2-ccc   2-ddd   2-eee
         /         |          \
       /           |            \
    3-fff        3-ggg           3-hhh
      |           /  \             /  \
      |         /      \         /      \
    4-iii    4-jjj    4-kkk   4-lll    4-mmm
                        |
                        |
                      5-nnn                        */
  VersionName v0_aaa(0, ImmutableData::name_type(Identity(std::string(64, 'a'))));
  VersionName v1_bbb(1, ImmutableData::name_type(Identity(std::string(64, 'b'))));
  VersionName v2_ccc(2, ImmutableData::name_type(Identity(std::string(64, 'c'))));
  VersionName v2_ddd(2, ImmutableData::name_type(Identity(std::string(64, 'd'))));
  VersionName v2_eee(2, ImmutableData::name_type(Identity(std::string(64, 'e'))));
  VersionName v3_fff(3, ImmutableData::name_type(Identity(std::string(64, 'f'))));
  VersionName v3_ggg(3, ImmutableData::name_type(Identity(std::string(64, 'g'))));
  VersionName v3_hhh(3, ImmutableData::name_type(Identity(std::string(64, 'h'))));
  VersionName v4_iii(4, ImmutableData::name_type(Identity(std::string(64, 'i'))));
  VersionName v4_jjj(4, ImmutableData::name_type(Identity(std::string(64, 'j'))));
  VersionName v4_kkk(4, ImmutableData::name_type(Identity(std::string(64, 'k'))));
  VersionName v4_lll(4, ImmutableData::name_type(Identity(std::string(64, 'l'))));
  VersionName v4_mmm(4, ImmutableData::name_type(Identity(std::string(64, 'm'))));
  VersionName v5_nnn(5, ImmutableData::name_type(Identity(std::string(64, 'n'))));
  VersionName absent(6, ImmutableData::name_type(Identity(std::string(64, 'x'))));
  VersionName v7_yyy(7, ImmutableData::name_type(Identity(std::string(64, 'y'))));
  VersionName v8_zzz(8, ImmutableData::name_type(Identity(std::string(64, 'z'))));
  std::vector<std::pair<VersionName, VersionName>> puts;
  puts.push_back(std::make_pair(VersionName(), v0_aaa));
  puts.push_back(std::make_pair(v0_aaa, v1_bbb));
  puts.push_back(std::make_pair(v1_bbb, v2_ccc));
  puts.push_back(std::make_pair(v2_ccc, v3_fff));
  puts.push_back(std::make_pair(v3_fff, v4_iii));
  puts.push_back(std::make_pair(v1_bbb, v2_ddd));
  puts.push_back(std::make_pair(v2_ddd, v3_ggg));
  puts.push_back(std::make_pair(v3_ggg, v4_jjj));
  puts.push_back(std::make_pair(v3_ggg, v4_kkk));
  puts.push_back(std::make_pair(v4_kkk, v5_nnn));
  puts.push_back(std::make_pair(v1_bbb, v2_eee));
  puts.push_back(std::make_pair(v2_eee, v3_hhh));
  puts.push_back(std::make_pair(v3_hhh, v4_lll));
  puts.push_back(std::make_pair(v3_hhh, v4_mmm));
  puts.push_back(std::make_pair(absent, v7_yyy));
  puts.push_back(std::make_pair(v7_yyy, v8_zzz));
  std::random_shuffle(std::begin(puts), std::end(puts));
  for (const auto& put : puts)
    versions.Put(put.first, put.second);
}

}  // unnamed namespace

TEST(StructuredDataVersionsTest, BEH_Put) {
  StructuredDataVersions versions(100, 10);
  VersionName old_version, new_version;
  for (uint32_t i(0); i != 100; ++i) {
    new_version = VersionName(i, RandomId());
    versions.Put(old_version, new_version);
    if (i % 20 == 0 && i != 0) {
      for (uint32_t j(0); j != (i / 20); ++j)
        AddBranch(versions, old_version, i, 20);
    }
    old_version = new_version;
  }
}

TEST(StructuredDataVersionsTest, BEH_PutOrphans) {
  StructuredDataVersions versions(1000, 100);
  VersionName old_version, new_version;
  std::vector<std::pair<VersionName, VersionName>> missing_names;
  for (uint32_t i(0); i != 100; ++i) {
    new_version = VersionName(i, RandomId());
    if (i % 20 == 0 && i != 0 && i != 20) {
      for (uint32_t j(0); j != (i / 20); ++j) {
        auto branch(AddBranch(versions, new_version, i, 20));
        AddBranch(versions, branch[7], i + 7, 20);
        AddBranch(versions, branch[14], i + 14, 20);
      }
      missing_names.push_back(std::make_pair(old_version, new_version));
    } else {
      versions.Put(old_version, new_version);
    }
    old_version = new_version;
  }

  for (const auto& missing_name : missing_names)
    versions.Put(missing_name.first, missing_name.second);
}

TEST(StructuredDataVersionsTest, BEH_Serialise) {
  StructuredDataVersions versions1(100, 10), versions2(100, 10);
  ConstructAsDiagram(versions1);
  ConstructAsDiagram(versions2);

  auto got_before1(versions1.Get());
  auto got_before2(versions2.Get());
  std::sort(std::begin(got_before1), std::end(got_before1));
  std::sort(std::begin(got_before2), std::end(got_before2));
  std::vector<std::vector<VersionName>> branches_before1, branches_before2;
  for (const auto& tot1 : got_before1)
    branches_before1.push_back(versions1.GetBranch(tot1));
  for (const auto& tot2 : got_before2)
    branches_before2.push_back(versions2.GetBranch(tot2));


  auto serialised1(versions1.Serialise());
  auto serialised2(versions2.Serialise());
  StructuredDataVersions parsed1(serialised1);
  StructuredDataVersions parsed2(serialised2);
  auto reserialised1(parsed1.Serialise());
  auto reserialised2(parsed2.Serialise());
  EXPECT_EQ(serialised1, reserialised1);
  EXPECT_EQ(serialised2, reserialised2);

  auto got_after1(parsed1.Get());
  auto got_after2(parsed2.Get());
  std::sort(std::begin(got_after1), std::end(got_after1));
  std::sort(std::begin(got_after2), std::end(got_after2));
  std::vector<std::vector<VersionName>> branches_after1, branches_after2;
  for (const auto& tot1 : got_after1)
    branches_after1.push_back(parsed1.GetBranch(tot1));
  for (const auto& tot2 : got_after2)
    branches_after2.push_back(parsed2.GetBranch(tot2));

  EXPECT_THAT(got_before1, testing::ContainerEq(got_after1));
  EXPECT_THAT(got_after1, testing::ContainerEq(got_after2));
  EXPECT_THAT(branches_before1, testing::ContainerEq(branches_after1));
  EXPECT_THAT(branches_after1, testing::ContainerEq(branches_after2));
}

}  // namespace test

}  // namespace maidsafe
