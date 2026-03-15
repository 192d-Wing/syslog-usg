# syslog-usg — Multi-stage Docker build
#
# Build:  docker build -t syslog-usg .
# Run:    docker run -v /path/to/config.toml:/etc/syslog-usg/config.toml syslog-usg
#
# The final image is ~15 MB (distroless/static) with no shell or libc.

# ---------------------------------------------------------------------------
# Stage 1: Build
# ---------------------------------------------------------------------------
FROM rust:1-trixie AS builder

WORKDIR /build

# Cache dependency downloads by copying manifests first
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates/syslog-proto/Cargo.toml crates/syslog-proto/Cargo.toml
COPY crates/syslog-parse/Cargo.toml crates/syslog-parse/Cargo.toml
COPY crates/syslog-transport/Cargo.toml crates/syslog-transport/Cargo.toml
COPY crates/syslog-relay/Cargo.toml crates/syslog-relay/Cargo.toml
COPY crates/syslog-config/Cargo.toml crates/syslog-config/Cargo.toml
COPY crates/syslog-observe/Cargo.toml crates/syslog-observe/Cargo.toml
COPY crates/syslog-server/Cargo.toml crates/syslog-server/Cargo.toml
COPY crates/syslog-sign/Cargo.toml crates/syslog-sign/Cargo.toml
COPY crates/syslog-mgmt/Cargo.toml crates/syslog-mgmt/Cargo.toml
COPY tests/integration/Cargo.toml tests/integration/Cargo.toml
COPY benches/syslog-bench/Cargo.toml benches/syslog-bench/Cargo.toml

# Create dummy source files so cargo can resolve the dependency graph
RUN for dir in \
    crates/syslog-proto/src \
    crates/syslog-parse/src \
    crates/syslog-transport/src \
    crates/syslog-relay/src \
    crates/syslog-config/src \
    crates/syslog-observe/src \
    crates/syslog-sign/src \
    crates/syslog-mgmt/src \
    tests/integration \
    benches/syslog-bench/benches; do \
    mkdir -p "$dir"; \
    done && \
    for crate in syslog-proto syslog-parse syslog-transport syslog-relay \
    syslog-config syslog-observe syslog-sign syslog-mgmt; do \
    echo "" > "crates/$crate/src/lib.rs"; \
    done && \
    echo "fn main() {}" > crates/syslog-server/src/main.rs && \
    mkdir -p crates/syslog-server/src && \
    echo "" > tests/integration/end_to_end.rs && \
    echo "" > tests/integration/hardening.rs && \
    echo "fn main() {}" > benches/syslog-bench/benches/parse.rs && \
    echo "fn main() {}" > benches/syslog-bench/benches/pipeline.rs && \
    echo "fn main() {}" > benches/syslog-bench/benches/outputs.rs

# Pre-build dependencies (cached layer)
RUN cargo build --release --bin syslog-usg 2>/dev/null || true

# Copy actual source and rebuild
COPY crates/ crates/
RUN cargo build --release --bin syslog-usg && \
    strip target/release/syslog-usg

# ---------------------------------------------------------------------------
# Stage 2: Runtime (distroless — no shell, no libc bloat)
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/static-debian12:nonroot

LABEL org.opencontainers.image.title="syslog-usg"
LABEL org.opencontainers.image.description="Production-grade RFC-compliant syslog server and relay"
LABEL org.opencontainers.image.source="https://github.com/syslog-usg/syslog-usg"

# Copy binary
COPY --from=builder /build/target/release/syslog-usg /usr/local/bin/syslog-usg

# Default config mount point
VOLUME ["/etc/syslog-usg"]

# State directory for RSID and replay detector persistence
VOLUME ["/var/lib/syslog-usg"]

# Syslog ports: UDP 514, TCP 514, TLS 6514, metrics 9090
EXPOSE 514/udp 514/tcp 6514/tcp 9090/tcp

# Run as nonroot user (UID 65534)
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/syslog-usg"]
CMD ["--config", "/etc/syslog-usg/config.toml"]
