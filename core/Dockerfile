# syntax=docker/dockerfile:1

FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS runner
WORKDIR /app

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV PORT=8080
ENV TMPDIR=/tmp

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./package.json
COPY src ./src

USER 1000:1000
EXPOSE 8080

ENTRYPOINT ["node", "src/server.js"]
