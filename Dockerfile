FROM rust:1.72.0-slim-bullseye AS build

WORKDIR /build/
COPY Cargo.toml Cargo.lock .
COPY src/. src/
COPY crates/. crates/

RUN cargo build --release

##

FROM debian:bullseye-20230904 AS final

COPY --from=build /build/target/release/wgslirpy /usr/bin/
CMD wgslirpy
