FROM node:20-bookworm-slim AS dependencies

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

FROM node:20-bookworm-slim AS runtime

ENV NODE_ENV=production
ENV PORT=3000
WORKDIR /app

COPY --from=dependencies /app/node_modules ./node_modules
COPY . ./

USER node
EXPOSE 3000
CMD ["node", "server.js"]
