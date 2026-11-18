/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#include <quic/common/MvfstLogging.h>

#include <gtest/gtest.h>

namespace quic::test {

TEST(MvfstLoggingTest, StreamMessages) {
  MVLOG_INFO << "logging test " << 42;
  MVVLOG(1) << "verbose logging test";
  MVVLOG_IF(1, false) << "conditional logging test";
  MVCHECK(true, "check message " << 42);
  MVDCHECK_EQ(1, 1, "debug check message");
}

#if MVFST_LOGGING_DISABLED
TEST(MvfstLoggingTest, DisabledLoggingPreservesChecks) {
  ASSERT_DEATH(MVCHECK(false, "failed check"), "");
}
#endif

} // namespace quic::test
