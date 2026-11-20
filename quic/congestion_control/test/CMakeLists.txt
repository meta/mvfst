# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

if(NOT BUILD_TESTS)
  return()
endif()

quic_add_test(TARGET CongestionControllerTests
  SOURCES
  BandwidthTest.cpp
  BbrBandwidthSamplerTest.cpp
  BbrRttSamplerTest.cpp
  BbrTest.cpp
  Bbr2Test.cpp
  Bbr3RateSamplerTest.cpp
  Bbr3Test.cpp
  C4Test.cpp
  CongestionControlFunctionsTest.cpp
  CopaTest.cpp
  CubicHystartTest.cpp
  CubicRecoveryTest.cpp
  CubicStateTest.cpp
  CubicSteadyTest.cpp
  CubicTest.cpp
  NewRenoTest.cpp
  PacerTest.cpp
  SimulatedTBFTest.cpp
  ThrottlingSignalProviderTest.cpp
  Utils.cpp
  DEPENDS
  Folly::folly
  mvfst_congestion_control_bbr3
  mvfst_congestion_control_bbr3_rate_sampler
  mvfst_congestion_control_c4
  mvfst_congestion_control_congestion_controller
  mvfst_congestion_control_pacer
  mvfst_congestion_control_simulated_tbf
  mvfst_state_state_functions
  mvfst_test_utils
)
