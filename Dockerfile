# Stage 1: Build stage
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293 AS builder

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
FROM node:20-alpine@sha256:fb4cd12c85ee03686f6af5362a0b0d56d50c58a04632e6c0fb8363f609372293

WORKDIR /app

# Set production env
ENV NODE_ENV=production

# Copy files needed to install production dependencies
COPY package.json package-lock.json ./
COPY packages/core/package.json ./packages/core/
COPY packages/cli/package.json ./packages/cli/

# Install only production dependencies
RUN npm ci --omit=dev

# Copy compiled artifacts from the builder stage
COPY --from=builder /app/packages/core/dist ./packages/core/dist
COPY --from=builder /app/packages/cli/dist ./packages/cli/dist

USER 10001

# Use entrypoint to run cli directly
ENTRYPOINT ["node", "packages/cli/dist/index.js"]
