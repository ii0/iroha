/**
 * Copyright Soramitsu Co., Ltd. All Rights Reserved.
 * SPDX-License-Identifier: Apache-2.0
 */

#include <gtest/gtest.h>
#include "module/shared_model/interface_mocks.hpp"
#include "validation/utils.hpp"

using namespace iroha::validation;
using namespace shared_model::crypto;

class SignaturesSubset : public testing::Test {
 public:
  std::vector<PublicKey> keys{PublicKey("a"), PublicKey("b"), PublicKey("c")};
};

/**
 * @given three different keys and three signatures with the same keys
 * @when signaturesSubset is executed
 * @then returned true
 */
TEST_F(SignaturesSubset, Equal) {
  std::array<SignatureMock, 3> signatures;
  for (size_t i = 0; i < signatures.size(); ++i) {
    EXPECT_CALL(signatures[i], publicKey())
        .WillRepeatedly(testing::ReturnRef(keys[i]));
  }
  ASSERT_TRUE(signaturesSubset(signatures, keys));
}

/**
 * @given two different keys and two signatures with the same keys plus
 * additional one
 * @when signaturesSubset is executed
 * @then returned false
 */
TEST_F(SignaturesSubset, Lesser) {
  std::vector<PublicKey> subkeys{keys.begin(), keys.end() - 1};
  std::array<SignatureMock, 3> signatures;
  for (size_t i = 0; i < signatures.size(); ++i) {
    EXPECT_CALL(signatures[i], publicKey())
        .WillRepeatedly(testing::ReturnRef(keys[i]));
  }
  ASSERT_FALSE(signaturesSubset(signatures, subkeys));
}

/**
 * @given three different keys and two signatures with the first pair of keys
 * @when signaturesSubset is executed
 * @then returned true
 */
TEST_F(SignaturesSubset, StrictSubset) {
  std::array<SignatureMock, 2> signatures;
  for (size_t i = 0; i < signatures.size(); ++i) {
    EXPECT_CALL(signatures[i], publicKey())
        .WillRepeatedly(testing::ReturnRef(keys[i]));
  }
  ASSERT_TRUE(signaturesSubset(signatures, keys));
}

/**
 * @given two same keys and two signatures with different keys
 * @when signaturesSubset is executed
 * @then returned false
 */
TEST_F(SignaturesSubset, PublickeyUniqueness) {
  std::vector<PublicKey> repeated_keys{2, keys[0]};
  std::array<SignatureMock, 2> signatures;
  for (size_t i = 0; i < signatures.size(); ++i) {
    EXPECT_CALL(signatures[i], publicKey())
        .WillRepeatedly(testing::ReturnRef(keys[i]));
  }
  ASSERT_FALSE(signaturesSubset(signatures, repeated_keys));
}
