# Builds one of the Rust sites: docker build --build-arg BIN=cert-site .
#                               docker build --build-arg BIN=consent-o-tron .
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
# Local file storage when no GCS_BUCKET is set (deployed, files go to the bucket).
RUN mkdir -p /app/data && chown nobody /app/data
# PKI material comes from Secret Manager as PKI_* environment variables.
ENV APP_ROOT=/app
USER nobody
CMD ["site"]
