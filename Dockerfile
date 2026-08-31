# syntax=docker/dockerfile:1.7

ARG NODE_VERSION=26.5.1
ARG PNPM_VERSION=11.15.1

FROM node:${NODE_VERSION}-alpine AS build

RUN apk upgrade --no-cache \
    && apk add --no-cache bash

WORKDIR /app
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY prisma ./prisma
RUN npm install --global pnpm@${PNPM_VERSION}
RUN pnpm install --frozen-lockfile
COPY . .
RUN pnpm run lint
RUN pnpm run build
RUN pnpm prune --prod
RUN node node_modules/prisma/build/index.js generate --schema=prisma/schema.prisma \
    && node node_modules/prisma/build/index.js generate --schema=prisma/group/schema.prisma \
    && node node_modules/prisma/build/index.js generate --schema=prisma/member/schema.prisma

FROM alpine:3.24 AS runtime

ARG NODE_VERSION
RUN apk upgrade --no-cache \
    && apk add --no-cache bash nodejs-current=${NODE_VERSION}-r0 \
    && addgroup -S -g 10001 app \
    && adduser -S -D -H -u 10001 -G app app

ARG RESET_DB_ARG=false
ENV RESET_DB=$RESET_DB_ARG
ARG SEED_DATA_ARG=""
ENV SEED_DATA=$SEED_DATA_ARG
ENV PRISMA_CLI_BINARY_TARGETS=linux-musl-openssl-3.0.x
ENV NODE_ENV=production

WORKDIR /app
COPY --from=build --chown=app:app /app/dist ./dist
COPY --from=build --chown=app:app /app/node_modules ./node_modules
COPY --from=build --chown=app:app /app/prisma ./prisma
COPY --from=build --chown=app:app /app/package.json ./package.json
COPY --from=build --chown=app:app /app/appStartUp.sh ./appStartUp.sh
RUN chmod +x appStartUp.sh
USER app
CMD ["./appStartUp.sh"]
