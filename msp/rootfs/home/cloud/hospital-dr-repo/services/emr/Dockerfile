# node:20-bookworm-slim amd64 manifest digest resolved for reproducible builds.
FROM node:20-bookworm-slim@sha256:3d0f05455dea2c82e2f76e7e2543964c30f6b7d673fc1a83286736d44fe4c41c AS dependencies

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:20-bookworm-slim@sha256:3d0f05455dea2c82e2f76e7e2543964c30f6b7d673fc1a83286736d44fe4c41c AS runtime

ENV NODE_ENV=production
ENV PORT=3000
WORKDIR /app

# Upgrade only OS packages with a published fix; do not perform a full distro upgrade.
RUN apt-get update \
    && apt-get install -y --no-install-recommends --only-upgrade libgnutls30 libcap2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=dependencies /app/node_modules ./node_modules
COPY . ./

# npm is needed only in the install stage; keep the runtime image Node-only.
RUN rm -rf /usr/local/lib/node_modules/npm \
    /usr/local/lib/node_modules/corepack \
    /usr/local/bin/npm \
    /usr/local/bin/npx \
    /usr/local/bin/corepack

USER node
EXPOSE 3000
CMD ["node", "server.js"]
