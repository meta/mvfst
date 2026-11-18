/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#pragma once

#include <quic/common/MvfstCheck.h>
#include <quic/quic-logging-config.h>

/**
 * quic/common/MvfstLogging.h defines the MVLOG_INFO, MVLOG_WARNING,
 * MVLOG_ERROR, MVLOG_FATAL, MVLOG_DFATAL, MVVLOG, and MVVLOG_IF macros.
 *
 * The backend is selected by exactly one of MVFST_LOGGING_GLOG,
 * MVFST_LOGGING_XLOG, or MVFST_LOGGING_DISABLED being defined to 1 in
 * <quic/quic-logging-config.h>. CMake derives that from
 * -DMVFST_LOGGING_BACKEND ({GLOG,XLOG,DISABLED}); Buck consumers pick a
 * hand-written variant via //quic:logging_config.
 *
 * Mobile builds compose with this selector orthogonally: under the GLOG
 * backend, mobile substitutes facebook/MvfstLogging-mobile.h (via the BUCK
 * select() in quic/common/BUCK) to strip non-fatal log strings from the
 * binary; XLOG and DISABLED don't need the mobile path (xlog has its own
 * build-time category levels, and DISABLED already strips everything).
 *
 * Authoring constraints:
 *   - MVVLOG(n): `n` must be an integer literal 0..9. Values >9 are accepted
 *     (saturated to DBG9 in xlog mode). For granularity finer than that, use
 *     the appropriate MVLOG_<level> instead.
 */

#if MVFST_LOGGING_GLOG

#include <glog/logging.h>

// Desktop/server version - pass through to glog without stripping.
// Mobile builds use MvfstLogging-mobile.h instead (via BUCK select()).

#define MVLOG_INFO LOG(INFO)
#define MVLOG_WARNING LOG(WARNING)
#define MVLOG_ERROR LOG(ERROR)
#define MVLOG_FATAL LOG(FATAL)
#define MVLOG_DFATAL LOG(DFATAL)

#define MVVLOG(n) VLOG(n)
#define MVVLOG_IF(n, condition) VLOG_IF(n, condition)

#elif MVFST_LOGGING_XLOG

#include <folly/logging/xlog.h>

// glog's VLOG(n) accepts arbitrary integer verbosity; folly's xlog only
// defines DBG0..DBG9. Map 0..9 directly; saturate higher values to DBG9 so
// MVVLOG(10+) call sites still compile in xlog mode.
#define MVFST_LOGGING_DBG_0 DBG0
#define MVFST_LOGGING_DBG_1 DBG1
#define MVFST_LOGGING_DBG_2 DBG2
#define MVFST_LOGGING_DBG_3 DBG3
#define MVFST_LOGGING_DBG_4 DBG4
#define MVFST_LOGGING_DBG_5 DBG5
#define MVFST_LOGGING_DBG_6 DBG6
#define MVFST_LOGGING_DBG_7 DBG7
#define MVFST_LOGGING_DBG_8 DBG8
#define MVFST_LOGGING_DBG_9 DBG9
#define MVFST_LOGGING_DBG_10 DBG9
#define MVFST_LOGGING_DBG_11 DBG9
#define MVFST_LOGGING_DBG_12 DBG9
#define MVFST_LOGGING_DBG_13 DBG9
#define MVFST_LOGGING_DBG_14 DBG9
#define MVFST_LOGGING_DBG_15 DBG9
#define MVFST_LOGGING_DBG_16 DBG9
#define MVFST_LOGGING_DBG_17 DBG9
#define MVFST_LOGGING_DBG_18 DBG9
#define MVFST_LOGGING_DBG_19 DBG9
#define MVFST_LOGGING_DBG_20 DBG9
#define MVFST_LOGGING_DBG_21 DBG9
#define MVFST_LOGGING_DBG_22 DBG9
#define MVFST_LOGGING_DBG_23 DBG9
#define MVFST_LOGGING_DBG_24 DBG9
#define MVFST_LOGGING_DBG_25 DBG9
#define MVFST_LOGGING_DBG_26 DBG9
#define MVFST_LOGGING_DBG_27 DBG9
#define MVFST_LOGGING_DBG_28 DBG9
#define MVFST_LOGGING_DBG_29 DBG9
#define MVFST_LOGGING_DBG_30 DBG9

#define MVLOG_INFO XLOG(INFO)
#define MVLOG_WARNING XLOG(WARN)
#define MVLOG_ERROR XLOG(ERR)
#define MVLOG_FATAL XLOG(FATAL)
#define MVLOG_DFATAL XLOG(DFATAL)

#define MVVLOG(n) XLOG(MVFST_LOGGING_DBG_##n)
#define MVVLOG_IF(n, condition) XLOG_IF(MVFST_LOGGING_DBG_##n, (condition))

#elif MVFST_LOGGING_DISABLED

// mvfst logging disabled. All log output is silently dropped; the macros
// still return a streamable sink so call-site `<< ...` chains compile.

#define MVLOG_INFO \
  ::quic::logging::detail::NoopStream {}
#define MVLOG_WARNING \
  ::quic::logging::detail::NoopStream {}
#define MVLOG_ERROR \
  ::quic::logging::detail::NoopStream {}
#define MVLOG_FATAL \
  ::quic::logging::detail::NoopStream {}
#define MVLOG_DFATAL \
  ::quic::logging::detail::NoopStream {}

#define MVVLOG(n) \
  ([](int) { return ::quic::logging::detail::NoopStream{}; }((n)))
#define MVVLOG_IF(n, condition)                                     \
  ([](int, bool) { return ::quic::logging::detail::NoopStream{}; }( \
       (n), static_cast<bool>(condition)))

#else
#error \
    "Exactly one of MVFST_LOGGING_GLOG, MVFST_LOGGING_XLOG, MVFST_LOGGING_DISABLED must be defined to 1 in <quic/quic-logging-config.h>"
#endif

// MVCHECK and MVDCHECK macros are defined in MvfstCheck.h
