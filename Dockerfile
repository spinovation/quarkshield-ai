# ========================================================
# Stage 1: Build Frontend UI Console (React + Vite)
# ========================================================
FROM node:22-alpine AS ui-builder
WORKDIR /app/ui

# Install dependencies
COPY ui/package*.json ./
RUN npm install

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
RUN npm install

# Copy source and compile
COPY server/ ./
RUN npm run build

# ========================================================
# Stage 3: Production Runner Image
# ========================================================
FROM node:22-alpine AS runner
RUN apk add --no-cache bash curl ca-certificates openssl git
RUN mkdir -p /app/certs && openssl req -x509 -newkey rsa:2048 -nodes -keyout /app/certs/key.pem -out /app/certs/cert.pem -days 3650 -subj "/CN=quarkshield.ai"

WORKDIR /app
ENV NODE_ENV=production
ENV PORT=5050
ENV HTTPS_PORT=5443
ENV SSL_CERT_PATH=/app/certs/cert.pem
ENV SSL_KEY_PATH=/app/certs/key.pem

# Install production server dependencies
COPY server/package*.json ./server/
RUN cd server && npm install --omit=dev

# Copy compiled server code & database schema
COPY --from=server-builder /app/server/dist ./server/dist
COPY --from=server-builder /app/server/src/models/schema.sql ./server/dist/models/schema.sql

# Copy compiled frontend UI bundle
COPY --from=ui-builder /app/ui/dist ./ui/dist

# Copy pre-compiled cross-platform scanner agent binaries
COPY agent/binaries ./agent/binaries

EXPOSE 5050

CMD ["node", "server/dist/index.js"]
