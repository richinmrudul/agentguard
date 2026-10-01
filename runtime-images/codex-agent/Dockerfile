# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 node:22.20.0-bookworm-slim@sha256:c385ec44d77c785e2364ac0c9b150809a0fdc17fde3dbf061e3dad07242c6a85 AS codex-download

WORKDIR /opt/codex-build
COPY package.json package-lock.json verify-integrity.mjs ./
RUN npm ci --ignore-scripts --omit=dev --no-audit --fund=false \
 && node verify-integrity.mjs

FROM --platform=linux/amd64 node:22.20.0-bookworm-slim@sha256:c385ec44d77c785e2364ac0c9b150809a0fdc17fde3dbf061e3dad07242c6a85

ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.title="AgentGuard Codex CLI Stage 1 agent"
LABEL org.opencontainers.image.source="https://github.com/richinmrudul/agentguard"
LABEL org.opencontainers.image.revision="${SOURCE_COMMIT}"
LABEL org.opencontainers.image.licenses="MIT"

ENV HOME=/nonexistent
ENV NO_UPDATE_NOTIFIER=1
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
ENV OPENAI_DISABLE_TELEMETRY=1
ENV CODEX_DISABLE_TELEMETRY=1
ENV PATH=/opt/codex/node_modules/.bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

WORKDIR /workspace
COPY --from=codex-download /opt/codex-build/node_modules /opt/codex/node_modules
COPY entrypoint.sh /usr/local/bin/agentguard-codex-entrypoint
RUN chmod 0555 /usr/local/bin/agentguard-codex-entrypoint \
 && mkdir -p /workspace \
 && chown 10001:10001 /workspace

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/agentguard-codex-entrypoint"]
