# syntax=docker/dockerfile:1.7
FROM --platform=linux/amd64 gcr.io/distroless/python3-debian13:nonroot@sha256:ab7db4566f1d345612bcd57e1d33d8beb428d111f477dac98521a98fa4ab754d

LABEL org.opencontainers.image.title="AgentGuard Stage 1 mock-only metering gateway"
LABEL org.opencontainers.image.source="https://github.com/richinmrudul/agentguard"
LABEL org.opencontainers.image.licenses="MIT"

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/opt/stage1
WORKDIR /
COPY --chmod=0555 agentguard/__init__.py /opt/stage1/agentguard/__init__.py
COPY --chmod=0555 agentguard/evaluation/__init__.py /opt/stage1/agentguard/evaluation/__init__.py
COPY --chmod=0555 agentguard/evaluation/stage1_metering.py /opt/stage1/agentguard/evaluation/stage1_metering.py
COPY --chmod=0555 agentguard/evaluation/stage1_metering_gateway.py /opt/stage1/agentguard/evaluation/stage1_metering_gateway.py

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/usr/bin/python3", "-m", "agentguard.evaluation.stage1_metering_gateway"]
