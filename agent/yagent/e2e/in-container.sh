#!/usr/bin/env bash
# Copyright 2026 Yahoo Inc.
# Licensed under the terms of the Apache License 2.0. Please see LICENSE file in project root for terms.

# Container side of run.sh: creates a SoftHSM token with one P-256 key, then
# runs the e2e test. The PIN is a throwaway test value.
set -euo pipefail

export SOFTHSM2_CONF=/tmp/softhsm2.conf
mkdir -p /tmp/tokens
echo "directories.tokendir = /tmp/tokens" >"$SOFTHSM2_CONF"

module="$(find /usr/lib -name libsofthsm2.so -print -quit)"
pin=123456
softhsm2-util --init-token --free --label yagent --pin "$pin" --so-pin 12345678 >/dev/null
pkcs11-tool --module "$module" --login --pin "$pin" \
  --keypairgen --key-type EC:prime256v1 --id 01 --label yagent-key >/dev/null

echo "ssh-agent: $(ssh -V 2>&1)"
echo "PKCS#11 module: $module"

YAGENT_E2E_PKCS11="$module" YAGENT_E2E_PIN="$pin" \
  go test -tags e2e -count=1 -v -run E2E ./agent/yagent/
