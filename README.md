<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">SPIFFE agent</h3>

<p align="center">Reads an X.509 SVID from a client-certificate header at the request-headers phase, checks the SPIFFE ID against an allowlist, and passes the identity to the upstream as headers.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-spiffe/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-spiffe/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Rust: 1.94.1+" src="https://img.shields.io/badge/rust-1.94.1%2B-f68d31?style=flat&labelColor=1f161e&logo=rust&logoColor=white">
  <img alt="Agent protocol: v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/spiffe/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

> [!WARNING]
> **Do not rely on this agent for authentication yet.** Its policy (allowlist,
> failure modes, header names; `require-mtls` also has a flag) can only be set through the
> agent protocol's configure event. Zentinel 26.10_8 and later send the agent
> block's `config { }` on every connection (releases up to 0.6.50 never did);
> on those releases, or without a `config { }` block, the agent runs with its
> defaults: mTLS not required, an empty allowlist that
> allows every SPIFFE ID, and no connection to the SPIRE Workload API, so
> certificates are not verified against a trust bundle (only parsed, checked for
> expiry and for a SPIFFE ID). Zentinel also does not set
> `X-Forwarded-Client-Cert` itself, so the header the agent reads is whatever the
> client or a TLS-terminating hop in front of Zentinel sent.
>
> Until the agent can verify a forwarded certificate against the SPIRE trust
> bundle ([#5](https://github.com/zentinelproxy/zentinel-agent-spiffe/issues/5)),
> it fails closed: it never treats `X-Forwarded-Client-Cert` as identity, so it
> never sets the identity headers, and with `require-mtls` it denies every
> request with `401`. The opt-in `tls.trust-forwarded-client-cert` is refused.
> Client-supplied identity headers are always removed.

For service-to-service traffic where each workload holds a SPIFFE X.509 SVID.
The agent takes the certificate from `X-Forwarded-Client-Cert` (PEM,
URL-encoded PEM, or base64 DER), validates it, matches the SPIFFE ID against an
allowlist (exact, prefix, regex, trust domain), and on success adds
`X-SPIFFE-Id`, `X-SPIFFE-Trust-Domain`, `X-SPIFFE-Workload-Id`,
`X-Auth-Method` and `X-Auth-Timestamp` to the upstream request. A rejected
certificate gets `401`, an ID outside the allowlist `403`, both with
`WWW-Authenticate: SPIFFE`.

## Quick start

```bash
zentinel bundle install spiffe
zentinel-spiffe-agent \
  --socket /var/run/zentinel/spiffe.sock \
  --spire-socket /run/spire/sockets/agent.sock
```

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "127.0.0.1:8080"
        protocol "http"
    }
}

agents {
    agent "spiffe" type="auth" {
        unix-socket "/var/run/zentinel/spiffe.sock"
        events "request_headers"
        timeout-ms 100
        failure-mode "closed"
    }
}

filters {
    filter "spiffe" {
        type "agent"
        agent "spiffe"
        failure-mode "closed"
    }
}

routes {
    route "api" {
        matches {
            path-prefix "/api/"
        }
        upstream "backend"
        filters "spiffe"
    }
}

upstreams {
    upstream "backend" {
        target "127.0.0.1:3000"
    }
}
```

See the warning above for what this enforces today.

## Install

**Bundle (recommended).** Downloads the release binary for your platform:

```bash
zentinel bundle install spiffe
```

See [the bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/).

**Cargo, from the repository.** The crate is not on crates.io; this builds the
`zentinel-spiffe-agent` binary from `main` (Rust 1.94.1 or newer, and `protoc`
for the Workload API bindings):

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-spiffe
```

**Release binaries.** Each [release](https://github.com/zentinelproxy/zentinel-agent-spiffe/releases)
ships `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` archives:

```bash
VERSION=0.3.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-spiffe-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-spiffe/releases/download/v${VERSION}/zentinel-spiffe-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-spiffe-agent.tar.gz
sudo install -m 0755 zentinel-spiffe-agent /usr/local/bin/
```

**From source.**

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-spiffe
cd zentinel-agent-spiffe
cargo build --release
```

## Configuration

Command-line flags, the only settings read at startup:

| Flag | Env | Default | Meaning |
|---|---|---|---|
| `--socket <PATH>` | `AGENT_SOCKET` | `/tmp/zentinel-spiffe.sock` | Unix socket to listen on |
| `--grpc-address <ADDR>` | `AGENT_GRPC_ADDRESS` | none | Serve gRPC on this address instead of the socket |
| `--spire-socket <PATH>` | `SPIRE_AGENT_SOCKET` | `/run/spire/sockets/agent.sock` | SPIRE agent socket; only connected to after a configure event |
| `--require-mtls` | `SPIFFE_REQUIRE_MTLS` | off | Start with `tls.require-mtls` set (unreleased, `main` only). A configure event replaces the whole configuration, this setting included |
| `-v, --verbose` | `SPIFFE_VERBOSE` | off | Debug logging |

Settings accepted through the configure event (JSON, kebab-case), which
Zentinel 26.10_8 and later fill from the agent block's `config { }` (over gRPC
only a build against `zentinel-agent-protocol` 0.6.51 or later receives it,
which the lockfile's 0.6.24 is not). A block the agent cannot parse, or one
that sets `tls.trust-forwarded-client-cert`, is refused; Zentinel then does
not use the agent and its filters' `failure-mode` applies. There is no
`--config` file option, so apart from `--require-mtls` none of these can be set
from the command line:

| Option | Default | Meaning |
|---|---|---|
| `spire.socket` | `/run/spire/sockets/agent.sock` | SPIRE Workload API socket |
| `spire.bundle-refresh-interval` | `300` | Seconds between trust bundle refreshes |
| `spire.api-timeout-ms` | `5000` | Workload API timeout |
| `tls.client-cert-header` | `X-Forwarded-Client-Cert` | Header carrying the client certificate |
| `tls.require-mtls` | `false` | Reject requests without a verified identity (currently every request, `401`); when `false` they pass without identity headers |
| `tls.trust-forwarded-client-cert` | `false` | Treat `client-cert-header` as identity because a trusted front proxy sets it. `true` is rejected until trust-bundle verification exists (#5) |
| `headers.spiffe-id` / `trust-domain` / `workload-id` / `auth-method` / `auth-timestamp` | `X-SPIFFE-Id` / `X-SPIFFE-Trust-Domain` / `X-SPIFFE-Workload-Id` / `X-Auth-Method` / `X-Auth-Timestamp` | Names of the headers added on success |
| `allowlist.exact` / `prefix` / `trust-domains` / `patterns` | all empty | Allowed SPIFFE IDs; all empty allows every ID |
| `failure.spire-unavailable` | `fail_closed` | `fail_open` turns any validation failure into an allow; `cache` behaves like `fail_closed` |
| `failure.validation-failure` | `reject` | `log_and_allow` lets certificates that fail validation through |
| `audit.log-success` | `true` | Log successful authentications |

Parsed but not used: `spire.svid-rotation-margin`, `failure.cache-ttl`,
`audit.log-failures`, `audit.include-spiffe-id`.

Proxy-side options (`events`, `timeout-ms`, `failure-mode`):
<https://docs.zentinelproxy.io/configuration/agents/>. Agent reference:
<https://registry.zentinelproxy.io/spiffe/>.

## How it works

1. Remove any client-supplied identity headers (the configured names and the
   defaults) from every request the agent lets through.
2. Without `trust-forwarded-client-cert` (always, for now) there is no
   verifiable identity: allow without identity, or `401` when `require-mtls`
   is set, regardless of the failure modes.
3. Read the certificate header (case-insensitive). Missing: allow, or `401`
   when `require-mtls` is set.
4. Decode the certificate, require a `spiffe://` URI SAN, reject it if expired.
5. Require that a CA from the trust bundle for the ID's trust domain signed it;
   an empty bundle rejects it.
6. Match the SPIFFE ID against the allowlist; outside it, `403`.
7. Allow, adding the identity headers to the upstream request.

The agent reports
`spiffe_agent_requests_total`, `..._allowed_total`, `..._blocked_total` and
`spiffe_agent_spire_connected` as v2 metrics, and reports itself degraded
while the SPIRE socket does not exist.

## Development

`protoc` is needed to build the Workload API bindings from
[`proto/workload.proto`](proto/workload.proto).

```bash
cargo fmt --all --check
cargo clippy --all-targets -- -D warnings
cargo test
```

Minimum Rust: 1.94.1 (`rust-version` in `Cargo.toml`).

## Related

- [Registry page](https://registry.zentinelproxy.io/spiffe/)
- [Agents configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)
- [Auth agent](https://github.com/zentinelproxy/zentinel-agent-auth), for JWT, API key and other request authentication

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
