FROM node:20-bookworm-slim AS dependencies

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:20-bookworm-slim AS runtime

ENV NODE_ENV=production
ENV PORT=3000
WORKDIR /app

COPY --from=dependencies /app/node_modules ./node_modules
COPY app.js package.json ./
COPY public ./public
COPY views ./views

# The host process uses loopback for PM2. Containers must listen on the
# container interface so the Compose port mapping can reach the app.
RUN sed -i "s/app\.listen(PORT, '127\.0\.0\.1'/app.listen(PORT, 'IP_REDACTED'/" app.js

USER node
EXPOSE 3000
CMD ["node", "app.js"]
