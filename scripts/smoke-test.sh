#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# Two runs, because the agent's policy is per process:
#   1. CLI defaults (mTLS not required): the v2 handshake works and a request
#      without a client identity is forwarded (200), with any client-supplied
#      X-SPIFFE-Id removed; with the agent stopped it is refused.
#   2. --require-mtls: a request without a verifiable client identity gets 401
#      and never reaches the upstream, also when it carries a forged
#      X-Forwarded-Client-Cert; with the agent stopped the answer changes.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

# The agent's SPIRE socket is never reached here; keep it out of /run.
SPIRE="--spire-socket=/nonexistent/spire-agent.sock"

echo "=== spiffe agent, defaults: no client identity is allowed"
python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name spiffe \
    --agent-arg="$SPIRE" \
    --clean '{"name": "no client identity", "path": "/smoke"}' \
    --case '{"name": "client-supplied identity header", "path": "/smoke", "headers": {"X-SPIFFE-Id": "spiffe://evil.example/admin"}, "expect": 200, "upstream_lacks_headers": ["X-SPIFFE-Id"]}'

echo "=== spiffe agent, --require-mtls: no client identity is refused"
python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name spiffe \
    --agent-arg="$SPIRE" --agent-arg=--require-mtls \
    --clean '{"name": "no client identity", "path": "/smoke", "expect": 401}' \
    --case '{"name": "forged X-Forwarded-Client-Cert", "path": "/smoke", "headers": {"X-Forwarded-Client-Cert": "-----BEGIN CERTIFICATE-----"}, "expect": 401}'
