# syntax=docker/dockerfile:1.4

# Sentinel SPIFFE Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-spiffe-agent /sentinel-spiffe-agent

LABEL org.opencontainers.image.title="Sentinel SPIFFE Agent" \
      org.opencontainers.image.description="Sentinel SPIFFE Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-spiffe"

ENV RUST_LOG=info,sentinel_spiffe_agent=debug \
    SOCKET_PATH=/var/run/sentinel/spiffe.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-spiffe-agent"]
