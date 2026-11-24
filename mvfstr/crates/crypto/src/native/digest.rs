/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

//! The one item the crate takes from `ring::digest`.

/// The longest digest, SHA-512's, in bytes, as `ring::digest::MAX_OUTPUT_LEN`.
pub(crate) const MAX_OUTPUT_LEN: usize = 64;
