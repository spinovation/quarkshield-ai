# ========================================================
# Stage 1: Build Frontend UI Console (React + Vite)
# ========================================================
FROM node:22-alpine AS ui-builder
WORKDIR /app/ui

# Install dependencies
COPY ui/package*.json ./
RUN npm ci --no-audit --no-fund

# Copy source and compile
COPY ui/ ./
RUN npm run build

# ========================================================
# Stage 2: Build Backend Server (TypeScript + Express)
# ========================================================
FROM node:22-alpine AS server-builder
WORKDIR /app/server

# Install dependencies
COPY server/package*.json ./
RUN npm ci --no-audit --no-fund

# Copy source and compile
COPY server/ ./
RUN npm run build

# ========================================================
# Stage 3: Production Runner Image
# ========================================================
FROM node:22-alpine AS runner
RUN apk add --no-cache bash curl ca-certificates openssl git
# The origin TLS key is generated at CONTAINER START (into a volume-backed dir), not
# baked into the image: a key in an image layer is shared by every container built
# from it and by anyone who can pull the image.
RUN mkdir -p /app/certs && chown -R node:node /app

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=5050
ENV HTTPS_PORT=5443
ENV SSL_CERT_PATH=/app/certs/cert.pem
ENV SSL_KEY_PATH=/app/certs/key.pem

# Install production server dependencies
COPY server/package*.json ./server/
RUN cd server && npm ci --omit=dev --no-audit --no-fund

# Copy compiled server code & database schema
COPY --from=server-builder /app/server/dist ./server/dist
COPY --from=server-builder /app/server/src/models/schema.sql ./server/dist/models/schema.sql

# Copy compiled frontend UI bundle
COPY --from=ui-builder /app/ui/dist ./ui/dist

# Copy pre-compiled cross-platform scanner agent binaries
COPY agent/binaries ./agent/binaries

# Copy enterprise & super admin documentation
COPY docs ./docs

COPY --chown=node:node docker-entrypoint.sh /app/docker-entrypoint.sh
RUN chmod +x /app/docker-entrypoint.sh && chown -R node:node /app

EXPOSE 5050
# Run unprivileged.
USER node

ENTRYPOINT ["/app/docker-entrypoint.sh"]
CMD ["node", "server/dist/index.js"]
