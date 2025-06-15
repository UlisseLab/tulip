ARG NODE_VERSION=lts

FROM node:${NODE_VERSION} AS builder
RUN corepack enable

WORKDIR /app
ENV YARN_GLOBAL_FOLDER=/app/.yarn

COPY .yarnrc.yml package.json yarn.lock ./
RUN --mount=type=cache,target=/app/.yarn/ \
    yarn install --immutable --inline-builds

COPY . ./
RUN yarn run build

FROM caddy
COPY --from=builder /app/dist /app/public
COPY Caddyfile /etc/caddy/Caddyfile

EXPOSE 3000
ENTRYPOINT [ "caddy", "run", "--config", "/etc/caddy/Caddyfile" ]
