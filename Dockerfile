# Builds one of the Rust sites: docker build --build-arg BIN=cert-site .
#                               docker build --build-arg BIN=consent-o-tron .
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

FROM rust:1-bookworm AS build
ARG BIN
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p "${BIN}"

FROM debian:bookworm-slim
ARG BIN
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates libssl3 \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/${BIN} /usr/local/bin/site
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
