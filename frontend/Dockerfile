ARG NODE_VERSION=lts

FROM node:${NODE_VERSION}
RUN corepack enable

WORKDIR /app
ENV YARN_GLOBAL_FOLDER=/app/.yarn

COPY .yarnrc.yml package.json yarn.lock ./
RUN --mount=type=cache,target=/app/.yarn/ \
    yarn install --immutable

COPY . ./
RUN yarn run build

EXPOSE 3000
CMD yarn run preview --host --port 3000
