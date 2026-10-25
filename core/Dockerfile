# syntax=docker/dockerfile:1

FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS deps
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev --ignore-scripts && npm cache clean --force

FROM node:22-alpine@sha256:fe4f6d74e20370acb04ad889077d14d0f64a9c8ea6a42bc60cddf1e844699914 AS runner
WORKDIR /app

# Google Cloud Confidential Space Launch Policy labels:
# https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/launch-policies
LABEL "tee.launch_policy.allow_env_override"="CORE_KEY_SOURCE,CORE_PUBLIC_ORIGIN,CORE_SECRETS_SOURCE"
LABEL "tee.launch_policy.log_redirect"="never"
LABEL "tee.launch_policy.monitoring_memory_allow"="never"

ENV NODE_ENV=production
ENV HOST=0.0.0.0
ENV TMPDIR=/tmp

COPY --from=deps /app/node_modules ./node_modules
COPY package.json ./package.json
COPY src ./src

# Non-root container user (UID/GID 1000:1000).
# Verified against the Confidential Space container_launcher implementation
# (github.com/google/go-tpm-tools/launcher): HostTmpPath (/run/container_launcher)
# is created with mode 0755 and listenUnixSocket() sets /run/container_launcher/teeserver.sock
# to mode 0777 (srwxrwxrwx), so non-root UID 1000 can connect to teeserver.sock directly.
USER 1000:1000
EXPOSE 8443

ENTRYPOINT ["node", "src/server.js"]
