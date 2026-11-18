# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

add_library(
  mvfst_test_utils
  TestPacketBuilders.cpp
  TestTransportUtils.cpp
  TestUtils.cpp
  AeadTestUtil.cpp
  CryptoTestUtil.cpp
  StringUtilsTest.cpp
)

set_property(TARGET mvfst_test_utils PROPERTY VERSION ${PACKAGE_VERSION})

target_include_directories(
  mvfst_test_utils PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}>
  ${LIBGMOCK_INCLUDE_DIR}
  ${LIBGTEST_INCLUDE_DIR}
)

target_compile_options(
  mvfst_test_utils
  PRIVATE
  ${_QUIC_COMMON_COMPILE_OPTIONS}
)

add_dependencies(
  mvfst_test_utils
  mvfst_fizz_client_handshake
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_folly_utils
  mvfst_server_server
  mvfst_state_quic_state_machine
  mvfst_api_transport
)

target_link_libraries(
  mvfst_test_utils PUBLIC
  Folly::folly
  ${LIBGMOCK_LIBRARIES}
  ${LIBGTEST_LIBRARIES}
  mvfst_fizz_client_handshake
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_folly_utils
  mvfst_server_server
  mvfst_state_quic_state_machine
  mvfst_common_string_utils
  mvfst_api_transport
  PRIVATE
  ${BOOST_LIBRARIES}
)

quic_add_test(TARGET QuicCommonUtilTest SOURCES
  MvfstLoggingTest.cpp
  FunctionLooperTest.cpp
  TimeUtilTest.cpp
  IntervalSetTest.cpp
  VariantTest.cpp
  BufAccessorTest.cpp
  BufUtilTest.cpp
  DEPENDS
  Folly::folly
  mvfst_api_transport_lite
  mvfst_common_buf_accessor
  mvfst_common_buf_util
  mvfst_common_events_folly_eventbase
  mvfst_common_events_highres_quic_timer
  mvfst_fizz_client_handshake
  mvfst_codec_pktbuilder
  mvfst_codec_types
  mvfst_folly_utils
  mvfst_common_string_utils
  mvfst_api_transport
  mvfst_server_server
  mvfst_state_quic_state_machine
  mvfst_test_utils
  ${BOOST_LIBRARIES}
)
