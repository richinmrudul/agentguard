"""Fake-only proof of the host-side, one-shot Unix credential handoff."""

from __future__ import annotations

import os
import socket
import struct
import sys
import threading
import time
from dataclasses import replace

import pytest

from agentguard.evaluation.stage1_credential_broker import (
    BrokerBinding,
    CredentialBrokerError,
    OneShotCredentialBroker,
    handoff_request,
)


CANARY = "FAKE_STAGE1_PRIVATE_PROVIDER_CANARY_7f54ab31"
LINUX_PEER = pytest.mark.skipif(sys.platform != "linux", reason="SO_PEERCRED is Linux-specific")


def _binding() -> BrokerBinding:
    digest = "sha256:" + "a" * 64
    return BrokerBinding(
        authorization_digest=digest,
        projection_digest=digest,
        nonce="b" * 64,
        study_id="study-a",
        trial_id="trial-a",
        gateway_subject=digest,
        gateway_canonical_identity=digest,
        gateway_binary_digest=digest,
        agent_subject=digest,
        agent_canonical_identity=digest,
        model="gpt-5.2-2025-12-11",
        destination="api.openai.com:443",
        pricing_digest=digest,
        credential_env_name="CODEX_API_KEY",
        expires_at_epoch=int(time.time()) + 60,
    )


def _send(path: str, payload: bytes) -> bytes:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.settimeout(3)
        client.connect(path)
        client.sendall(payload)
        client.shutdown(socket.SHUT_WR)
        return client.recv(1024)


def test_binding_rejects_wrong_scope_and_expiry() -> None:
    binding = _binding()
    assert CANARY.encode() not in handoff_request(binding)
    for change in (
        {"nonce": "short"},
        {"model": "gpt-5.2"},
        {"destination": "localhost:443"},
        {"credential_env_name": "OTHER_KEY"},
        {"gateway_binary_digest": "bad"},
        {"expires_at_epoch": 0},
    ):
        with pytest.raises(CredentialBrokerError):
            handoff_request(replace(binding, **change))


@LINUX_PEER
def test_one_shot_fake_handoff_cleans_socket_and_never_reads_early(tmp_path) -> None:
    binding = _binding()
    calls: list[str] = []
    broker = OneShotCredentialBroker(
        binding, tmp_path, expected_peer_uid=os.getuid(),
        credential_source=lambda: calls.append("read") or CANARY,
    )
    path = str(broker.socket_path)
    assert broker.socket_path.stat().st_mode & 0o777 == 0o600
    assert broker.socket_path.parent.stat().st_mode & 0o777 == 0o700
    assert calls == []
    received: list[bytes] = []
    client = threading.Thread(target=lambda: received.append(_send(path, handoff_request(binding))))
    client.start()
    broker.serve_once()
    client.join(timeout=3)
    assert not client.is_alive()
    assert calls == ["read"]
    assert received == [struct.pack("!I", len(CANARY)) + CANARY.encode()]
    assert not os.path.exists(path)
    assert not os.path.exists(os.path.dirname(path))
    with pytest.raises(CredentialBrokerError, match="already been used"):
        broker.serve_once()


@pytest.mark.parametrize("fault", ["wrong-binding", "truncated", "oversized", "wrong-peer"])
@LINUX_PEER
def test_broker_denies_before_fake_credential_read(tmp_path, fault: str) -> None:
    binding = _binding()
    calls: list[str] = []
    broker = OneShotCredentialBroker(
        binding, tmp_path,
        expected_peer_uid=os.getuid() + (fault == "wrong-peer"),
        credential_source=lambda: calls.append("read") or CANARY,
    )
    payload = handoff_request(binding)
    if fault == "wrong-binding":
        payload = handoff_request(replace(binding, nonce="c" * 64))
    elif fault == "truncated":
        payload = payload[:6]
    elif fault == "oversized":
        payload = struct.pack("!I", 4097)

    def rejected_client() -> None:
        try:
            _send(str(broker.socket_path), payload)
        except OSError:
            pass

    client = threading.Thread(target=rejected_client)
    client.start()
    with pytest.raises(CredentialBrokerError, match="handoff denied"):
        broker.serve_once()
    client.join(timeout=3)
    assert not client.is_alive()
    assert calls == []
    assert not list(tmp_path.iterdir())


@LINUX_PEER
def test_broker_redacts_credential_source_failure(tmp_path) -> None:
    def fail_source() -> str:
        raise RuntimeError(f"secret source failed: {CANARY}")

    broker = OneShotCredentialBroker(
        _binding(), tmp_path, expected_peer_uid=os.getuid(), credential_source=fail_source,
    )
    def rejected_client() -> None:
        try:
            _send(str(broker.socket_path), handoff_request(_binding()))
        except OSError:
            pass

    client = threading.Thread(target=rejected_client)
    client.start()
    with pytest.raises(CredentialBrokerError) as denied:
        broker.serve_once()
    client.join(timeout=3)
    assert not client.is_alive()
    assert CANARY not in str(denied.value)
    assert not list(tmp_path.iterdir())


@LINUX_PEER
def test_broker_rejects_socket_substitution_before_accept(tmp_path) -> None:
    calls: list[str] = []
    broker = OneShotCredentialBroker(
        _binding(), tmp_path, expected_peer_uid=os.getuid(),
        credential_source=lambda: calls.append("read") or CANARY,
    )
    broker.socket_path.unlink()
    broker.socket_path.touch()
    with pytest.raises(CredentialBrokerError):
        broker.serve_once()
    assert calls == []
    assert not list(tmp_path.iterdir())
