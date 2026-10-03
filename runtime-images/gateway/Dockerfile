# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 python:3.12.12-slim-bookworm@sha256:2986c55feb36e6cae00fa1fefb454283e4b33f35e75ff8bdd123b134130be301

ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.title="AgentGuard live-study egress gateway"
LABEL org.opencontainers.image.source="https://github.com/richinmrudul/agentguard"
LABEL org.opencontainers.image.revision="${SOURCE_COMMIT}"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /
COPY agentguard_live_egress_gateway.py /agentguard-live-egress-gateway
RUN chmod 0555 /agentguard-live-egress-gateway

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/agentguard-live-egress-gateway"]
