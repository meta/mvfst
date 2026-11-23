#!/usr/bin/env bash
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# Prints "<crate> <version> <state>" for each publishable workspace crate. The
# state is "published" when crates.io has that version, "new" when crates.io
# has no crate by that name, and "update" otherwise.

set -euo pipefail

index=
rc=
for sig in 1 2 3 13 15; do eval "trap 'exit $((sig + 128))' $sig"; done
trap 'rc=$?; set +e; rm -f "$index"; exit $rc' EXIT
index=$(mktemp)

crates=$(cargo metadata --no-deps --format-version 1 \
  | jq -r '.packages[]
      | select(.publish == null or (.publish | index("crates-io")))
      | "\(.name) \(.version)"')

while read -r name version; do
  lower=${name,,}
  if (( ${#lower} < 4 )); then
    echo "$name: only names of four or more characters are supported" >&2
    exit 1
  fi
  status=$(curl -sS --retry 5 --retry-connrefused -o "$index" -w '%{http_code}' \
    "https://index.crates.io/${lower:0:2}/${lower:2:2}/$lower")
  case "$status" in
    200)
      found=$(jq -n --arg v "$version" 'any(inputs; .vers == $v)' "$index")
      if [[ $found == true ]]; then state=published; else state=update; fi
      ;;
    404) state=new ;;
    *)
      echo "the crates.io index returned HTTP $status for $name" >&2
      exit 1
      ;;
  esac
  echo "$name $version $state"
done <<<"$crates"
