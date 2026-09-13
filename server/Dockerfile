# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

FROM node:26.8-alpine3.23@sha256:a3024faf41c40992531ecfb00604384665be870a44626afaf181c6d583f89296 AS build

WORKDIR /app

COPY server/package*.json ./
RUN npm ci

COPY server/tsconfig.json ./
COPY server/src ./src
RUN npm run build \
    && npm prune --omit=dev

FROM node:26.8-alpine3.23@sha256:a3024faf41c40992531ecfb00604384665be870a44626afaf181c6d583f89296

ENV NODE_ENV=production
WORKDIR /app

RUN apk upgrade --no-cache \
    && rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/bin/npm \
    /usr/local/bin/npx

COPY --from=build --chown=node:node /app/package.json /app/package-lock.json ./
COPY --from=build --chown=node:node /app/node_modules ./node_modules
COPY --from=build --chown=node:node /app/dist ./dist

USER node
EXPOSE 3003

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:3003/health').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"

CMD ["node", "dist/index.js"]
