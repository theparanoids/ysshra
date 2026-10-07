#!/usr/bin/env bash
# Copyright 2026 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

# Runs the yagent end-to-end test against SoftHSM and a stock OpenSSH
# ssh-agent inside a container. Usage, from anywhere in the repo:
#
#   agent/yagent/e2e/run.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../../.." && pwd)"
image=ysshra-yagent-e2e

docker build -q -t "$image" "$here" >/dev/null
docker run --rm -v "$repo:/src:ro" -w /src \
  -e GOFLAGS=-buildvcs=false \
  "$image" bash /src/agent/yagent/e2e/in-container.sh
