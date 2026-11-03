# The login application, for a deployment (docker-compose.prod.yml; docs/deploy.md).
# Local work runs it on the host with `npm run dev` instead.

FROM node:22-alpine AS build
WORKDIR /app
# package.json pins npm 11.6.2: npm 11.3 crashes resolving this dependency tree.
RUN npm install -g npm@11.6.2
COPY package.json package-lock.json ./
RUN npm ci
COPY tsconfig.json tsconfig.build.json nest-cli.json ./
COPY src src
RUN npm run build && npm prune --omit=dev

FROM node:22-alpine
# bash, curl, jq and envsubst (gettext) for the one-time setup (scripts/deploy-setup.sh);
# tini so the server gets signals and shuts down cleanly.
RUN apk add --no-cache bash curl jq gettext tini
WORKDIR /app
ENV NODE_ENV=production
COPY --from=build /app/node_modules node_modules
COPY --from=build /app/dist dist
COPY package.json ./
COPY views views
COPY public public
COPY db db
COPY scripts scripts
COPY deploy deploy
USER node
EXPOSE 3100
ENTRYPOINT ["/sbin/tini", "--"]
CMD ["node", "dist/main.js"]
