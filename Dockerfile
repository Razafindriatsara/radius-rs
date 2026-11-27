# radius-rs als schlankes Container-Image (zweistufiger Build)
#
#   docker build -t radius-rs .
#   docker run --rm -p 1812:1812/udp -p 1813:1813/udp radius-rs
#
# Eigene Konfiguration einbinden:
#   docker run --rm -p 1812:1812/udp -p 1813:1813/udp \
#     -v "$PWD/config.toml:/etc/radius-rs/config.toml:ro" -v radius-data:/data radius-rs

# ---- Build ------------------------------------------------------------------
FROM rust:1-slim-bookworm AS build
WORKDIR /src
# Abhängigkeiten zuerst bauen, damit Docker sie bei Codeänderungen aus dem Cache nimmt
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src/bin && echo 'fn main() {}' > src/main.rs && echo 'fn main() {}' > src/bin/radius-client.rs \
    && echo 'fn main() {}' > src/bin/radius-portal.rs \
    && touch src/lib.rs && cargo build --release --locked && rm -rf src
COPY src ./src
RUN touch src/lib.rs src/main.rs src/bin/radius-client.rs src/bin/radius-portal.rs && cargo build --release --locked --bins

# ---- Laufzeit ---------------------------------------------------------------
FROM debian:bookworm-slim
RUN useradd --system --uid 10001 --home-dir /data radius \
    && mkdir -p /data /etc/radius-rs && chown radius /data
COPY --from=build /src/target/release/radius-rs /src/target/release/radius-client /src/target/release/radius-portal /usr/local/bin/
COPY docker/config.toml /etc/radius-rs/config.toml

USER radius
WORKDIR /data
VOLUME /data
EXPOSE 1812/udp 1813/udp 3799/udp 8080/tcp 8090/tcp
ENTRYPOINT ["radius-rs"]
CMD ["/etc/radius-rs/config.toml"]
