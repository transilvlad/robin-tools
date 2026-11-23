# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

# Frontend assets are architecture-independent; keep Vite off QEMU.
FROM --platform=$BUILDPLATFORM node:26.13.1-alpine3.23@sha256:39d8c143e60e99ae98f014bebea1e72fc96d3c9bdf9504bc3a27af5c05bfa39f AS build

WORKDIR /app

RUN apk add --no-cache "libexpat>=2.9.0-r0"

COPY package.json package-lock.json ./
RUN npm ci

COPY index.html vite.config.ts tsconfig.json tsconfig.app.json tsconfig.node.json ./
COPY src ./src
RUN npm run build

FROM nginx:1.31.9-alpine@sha256:fb4658584bd9a916ffb6f6e365f97c25cfdb2923801f551ea08356e695f14ff7

RUN apk upgrade --no-cache \
    && apk add --no-cache "libexpat>=2.9.0-r0" 'pcre2>=10.49-r0' 'tiff>=4.7.2-r0' 'curl>=8.23.0-r0' 'libcurl>=8.23.0-r0' 'libxslt>=1.1.43-r4' 'libxml2>=2.13.9-r3' libcap \
    && setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx \
    && touch /run/nginx.pid \
    && chown -R nginx:nginx /var/cache/nginx /run/nginx.pid /etc/nginx/conf.d

COPY --chown=nginx:nginx nginx.conf /etc/nginx/conf.d/default.conf
COPY --from=build --chown=nginx:nginx /app/dist /usr/share/nginx/html

USER nginx
EXPOSE 80

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD wget -q -O /dev/null http://127.0.0.1/healthz || exit 1
