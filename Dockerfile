# Stage 1: Build stage
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402 AS builder

WORKDIR /app

# Copy lockfile and package descriptions
COPY package.json package-lock.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/cli/package.json ./packages/cli/

# Install all dependencies (including dev dependencies for build)
RUN npm ci

# Copy source code
COPY packages/core ./packages/core
COPY packages/cli ./packages/cli

# Build core and cli packages
RUN npm run build

# Stage 2: Production runner stage
FROM node:22-alpine@sha256:0a7108bf6c7bf5de370ffb1a3ed6be93d405b43ff159f681a8d18c0e2bc2e402

WORKDIR /app

# Set production env
ENV NODE_ENV=production

# Copy files needed to install production dependencies
COPY package.json package-lock.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/cli/package.json ./packages/cli/

# Apply latest Alpine security patches, install production dependencies, and remove unneeded package manager tooling
RUN apk upgrade --no-cache \
    && npm ci --omit=dev \
    && npm cache clean --force \
    && rm -rf /root/.npm /usr/local/lib/node_modules/npm /usr/local/bin/npm /usr/local/bin/npx /opt/yarn* /usr/local/lib/node_modules/corepack

# Copy compiled artifacts from the builder stage
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/cli/dist ./packages/cli/dist

USER 10001

# Use entrypoint to run cli directly
ENTRYPOINT ["node", "packages/cli/dist/index.js"]
