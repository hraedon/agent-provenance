#!/usr/bin/env bash
# Launch opencode with Cairn provenance plugin environment.
# Source this or run it directly.

export CAIRN_DSN="${CAIRN_DSN:-postgresql://regista_test:regista_test@localhost:5432/regista_test}"
export CAIRN_PROJECT="${CAIRN_PROJECT:-cairn_live_test}"
export CAIRN_KEY_PATH="${CAIRN_KEY_PATH:-/tmp/cairn_live_key.json}"
export CAIRN_BRIDGE_PATH="${CAIRN_BRIDGE_PATH:-/projects/agent-provenance/integrations/opencode/cairn-bridge.sh}"
export PRINCIPAL_ID="${PRINCIPAL_ID:-human:itadmin}"
export CAIRN_HARNESS_NAME="opencode"
export CAIRN_HARNESS_VERSION="$(opencode --version 2>/dev/null || echo unknown)"
export CAIRN_ATTEST_ON_START=1

exec opencode "$@"
