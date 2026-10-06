# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 node:22.20.0-bookworm-slim@sha256:c385ec44d77c785e2364ac0c9b150809a0fdc17fde3dbf061e3dad07242c6a85 AS codex-download

WORKDIR /opt/codex-build
COPY package.json package-lock.json verify-integrity.mjs entrypoint.c ./
RUN npm ci --ignore-scripts --omit=dev --no-audit --fund=false \
 && node verify-integrity.mjs \
 && apt-get update \
 && apt-get install -y --no-install-recommends gcc libc6-dev \
 && rm -rf /var/lib/apt/lists/* \
 && gcc -O2 -static -s -o /usr/local/bin/agentguard-codex-entrypoint entrypoint.c \
 && mkdir -p /opt/codex-runtime/bin /opt/codex-runtime/codex-path /opt/codex-runtime/codex-resources \
 && cp node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex /opt/codex-runtime/bin/codex \
 && cp node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/bin/codex-code-mode-host /opt/codex-runtime/bin/codex-code-mode-host \
 && cp node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-path/rg /opt/codex-runtime/codex-path/rg \
 && cp node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-resources/bwrap /opt/codex-runtime/codex-resources/bwrap \
 && cp node_modules/@openai/codex-linux-x64/vendor/x86_64-unknown-linux-musl/codex-package.json /opt/codex-runtime/codex-package.json \
 && cp node_modules/@openai/codex-linux-x64/README.md /opt/codex-runtime/CODEX-LINUX-X64-README.md \
 && cp node_modules/@openai/codex/README.md /opt/codex-runtime/CODEX-README.md \
 && printf 'agentguard:x:10001:10001:AgentGuard Codex:/workspace:/sbin/nologin\n' > /opt/codex-runtime/passwd \
 && printf 'agentguard:x:10001:\n' > /opt/codex-runtime/group \
 && chmod 0555 /usr/local/bin/agentguard-codex-entrypoint /opt/codex-runtime/bin/codex /opt/codex-runtime/bin/codex-code-mode-host /opt/codex-runtime/codex-path/rg /opt/codex-runtime/codex-resources/bwrap

FROM --platform=linux/amd64 gcr.io/distroless/static-debian12:nonroot@sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d

ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.title="AgentGuard Codex CLI Stage 1 agent"
LABEL org.opencontainers.image.source="https://github.com/richinmrudul/agentguard"
LABEL org.opencontainers.image.revision="${SOURCE_COMMIT}"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.base.name="gcr.io/distroless/static-debian12:nonroot"
LABEL org.opencontainers.image.base.digest="sha256:52dcfbabb7457ea47c82f6e13af8c8a4a1d9f7b0145142b3ecab20f2b888411d"

ENV HOME=/nonexistent
ENV NO_UPDATE_NOTIFIER=1
ENV NPM_CONFIG_UPDATE_NOTIFIER=false
ENV OPENAI_DISABLE_TELEMETRY=1
ENV CODEX_DISABLE_TELEMETRY=1
ENV PATH=/usr/local/bin:/opt/codex/bin:/opt/codex/codex-path

WORKDIR /workspace
COPY --from=codex-download /opt/codex-runtime/passwd /etc/passwd
COPY --from=codex-download /opt/codex-runtime/group /etc/group
COPY --from=codex-download /usr/local/bin/agentguard-codex-entrypoint /usr/local/bin/agentguard-codex-entrypoint
COPY --from=codex-download /opt/codex-runtime /opt/codex
COPY --chown=10001:10001 --chmod=0755 workspace /workspace

USER 10001:10001
ENTRYPOINT ["/usr/local/bin/agentguard-codex-entrypoint"]
