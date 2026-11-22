# Builds the Rust sites, one image per target:
#   docker build --target cert-site .
#   docker build --target consent-o-tron .
# Both targets share one cargo build, and cargo-chef keeps the dependencies in
# their own layer so a source change only recompiles the workspace crates.

# NotSSL's React home page, served by cert-site (other images ignore it).
FROM node:22-bookworm-slim AS web
WORKDIR /web
COPY crates/cert-site/web/package.json crates/cert-site/web/package-lock.json ./
RUN npm ci
COPY crates/cert-site/web ./
RUN npm run build

# Consent-O-Tron's React pages, served by consent-o-tron.
FROM node:22-bookworm-slim AS web-consent
WORKDIR /web
COPY crates/consent-o-tron/web/package.json crates/consent-o-tron/web/package-lock.json ./
RUN npm ci
COPY crates/consent-o-tron/web ./
RUN npm run build

FROM rust:1-bookworm AS chef
RUN cargo install cargo-chef --locked --version ^0.1
WORKDIR /src

# The recipe only changes when a manifest or the lockfile does.
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS build
COPY --from=planner /src/recipe.json recipe.json
# Same packages as the build below, so the features (and the cache) match.
RUN cargo chef cook --release --locked -p cert-site -p consent-o-tron --recipe-path recipe.json
COPY . .
RUN cargo build --release --locked -p cert-site -p consent-o-tron

FROM debian:bookworm-slim AS runtime
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY schemas /app/schemas
COPY templates /app/templates
COPY --from=web /web/dist /app/crates/cert-site/web/dist
COPY --from=web-consent /web/dist /app/crates/consent-o-tron/web/dist
# Local file storage when no GCS_BUCKET is set (deployed, files go to the bucket).
RUN mkdir -p /app/data && chown nobody /app/data
# PKI material comes from Secret Manager as PKI_* environment variables.
ENV APP_ROOT=/app
USER nobody
CMD ["site"]

FROM runtime AS consent-o-tron
COPY --from=build /src/target/release/consent-o-tron /usr/local/bin/site

FROM runtime AS cert-site
COPY --from=build /src/target/release/cert-site /usr/local/bin/site
