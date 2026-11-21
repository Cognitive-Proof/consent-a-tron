# The wallet is static. Site URLs are baked in at build time:
# docker build --build-arg VITE_CERT_SITE_URL=… --build-arg VITE_CONSENT_SITE_URL=… wallet
FROM node:22-alpine AS build
WORKDIR /w
COPY package.json package-lock.json ./
RUN npm ci --no-fund --no-audit
COPY . .
ARG VITE_CERT_SITE_URL
ARG VITE_CONSENT_SITE_URL
RUN npm run build

FROM nginx:1.27-alpine
COPY --from=build /w/dist /usr/share/nginx/html
# Rendered at start-up with FRAME_ANCESTORS (the two sites allowed to embed the wallet).
COPY nginx.conf.template /etc/nginx/templates/default.conf.template
ENV FRAME_ANCESTORS="http://localhost:4001 http://localhost:4003"
