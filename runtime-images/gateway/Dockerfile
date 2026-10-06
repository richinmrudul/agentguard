# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 gcr.io/distroless/python3-debian13:nonroot@sha256:339ecee37afe554f5237b9993250bc390ac9f1483a08c9b5e77ac4c016d6d39a

ARG SOURCE_COMMIT=unknown
LABEL org.opencontainers.image.title="AgentGuard live-study egress gateway"
LABEL org.opencontainers.image.source="https://github.com/richinmrudul/agentguard"
LABEL org.opencontainers.image.revision="${SOURCE_COMMIT}"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.base.name="gcr.io/distroless/python3-debian13:nonroot"
LABEL org.opencontainers.image.base.digest="sha256:339ecee37afe554f5237b9993250bc390ac9f1483a08c9b5e77ac4c016d6d39a"

ENV PYTHONDONTWRITEBYTECODE=1
WORKDIR /
COPY --chmod=0555 agentguard_live_egress_gateway.py /agentguard-live-egress-gateway

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/bin/python3", "/agentguard-live-egress-gateway"]
