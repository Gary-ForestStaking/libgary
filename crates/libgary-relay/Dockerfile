# Build from repository root:
#   docker build -f crates/libgary-relay/Dockerfile -t libgary-relay:latest .
FROM rust:1.95-bookworm AS builder
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
RUN cargo build --release -p libgary-relay --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/libgary-relay /usr/local/bin/libgary-relay
ENV PORT=8080
EXPOSE 8080
USER nobody:nogroup
CMD ["/usr/local/bin/libgary-relay"]
