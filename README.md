# zentinel-agent-spiffe

SPIFFE/SPIRE workload identity agent for Zentinel reverse proxy.

## Installation

### Using Bundle (Recommended)

```bash
# Install just this agent
zentinel bundle install spiffe

# Or install all bundled agents
zentinel bundle install
```

The bundle command downloads the correct binary for your platform and places it in the standard location. See the [bundle documentation](https://docs.zentinelproxy.io/deployment/bundle/) for details.

### Using Cargo

`zentinel-agent-spiffe` is not published on crates.io, so `cargo install zentinel-agent-spiffe` does not
work. Install straight from the repository instead:

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-spiffe
```

This builds and installs the `zentinel-spiffe-agent` binary.

### Prebuilt Binaries

Each [release](https://github.com/zentinelproxy/zentinel-agent-spiffe/releases) ships binaries
for `linux-x86_64`, `linux-aarch64`, and `darwin-aarch64`:

```bash
VERSION=0.3.0
PLATFORM=linux-x86_64   # or linux-aarch64, darwin-aarch64
curl -fsSL -o zentinel-spiffe-agent.tar.gz \
  "https://github.com/zentinelproxy/zentinel-agent-spiffe/releases/download/v${VERSION}/zentinel-spiffe-agent-${VERSION}-${PLATFORM}.tar.gz"
tar -xzf zentinel-spiffe-agent.tar.gz
sudo install -m 0755 zentinel-spiffe-agent /usr/local/bin/
```

### From Source

```bash
git clone https://github.com/zentinelproxy/zentinel-agent-spiffe
cd zentinel-agent-spiffe
cargo build --release
```

## Documentation

See [zentinelproxy.io/docs/agents/spiffe](https://docs.zentinelproxy.io/agents/spiffe)

## License

Apache-2.0
