"""One-shot host credential handoff for a future Stage 1 gateway session.

This module does not activate a live study. A caller must first validate the
authoritative authorization and its projection, then supply their exact binding.
"""

from __future__ import annotations

import hmac
import json
import os
import re
import socket
import stat
import struct
import sys
import tempfile
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable


_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
_ID = re.compile(r"[a-z0-9][a-z0-9-]{0,79}\Z")
_TOKEN = re.compile(rb"[A-Za-z0-9_-]{16,512}\Z")
_MAX_FRAME = 4096
_SCHEMA = "agentguard.stage1-credential-handoff"


class CredentialBrokerError(ValueError):
    """A sanitized handoff denial; never includes request or credential bytes."""


@dataclass(frozen=True)
class BrokerBinding:
    authorization_digest: str
    projection_digest: str
    nonce: str
    study_id: str
    trial_id: str
    gateway_subject: str
    gateway_canonical_identity: str
    gateway_binary_digest: str
    agent_subject: str
    agent_canonical_identity: str
    model: str
    destination: str
    pricing_digest: str
    credential_env_name: str
    expires_at_epoch: int

    def validate(self, *, now: int | None = None) -> None:
        for value in (
            self.authorization_digest, self.projection_digest,
            self.gateway_canonical_identity, self.gateway_binary_digest,
            self.agent_canonical_identity, self.pricing_digest,
        ):
            if not _DIGEST.fullmatch(value):
                raise CredentialBrokerError("handoff identity is invalid")
        if not re.fullmatch(r"[0-9a-f]{64}", self.nonce):
            raise CredentialBrokerError("handoff nonce is invalid")
        if not all(_ID.fullmatch(value) for value in (self.study_id, self.trial_id)):
            raise CredentialBrokerError("handoff scope is invalid")
        if not all(_DIGEST.fullmatch(value) for value in (self.gateway_subject, self.agent_subject)):
            raise CredentialBrokerError("handoff candidate identity is invalid")
        if (self.model != "gpt-5.2-2025-12-11"
                or self.destination != "api.openai.com:443"
                or self.credential_env_name != "CODEX_API_KEY"):
            raise CredentialBrokerError("handoff provider scope is invalid")
        current = int(time.time()) if now is None else now
        if (isinstance(self.expires_at_epoch, bool)
                or not isinstance(self.expires_at_epoch, int)
                or self.expires_at_epoch <= current
                or self.expires_at_epoch > current + 7 * 24 * 60 * 60):
            raise CredentialBrokerError("handoff deadline is invalid")


def handoff_request(binding: BrokerBinding) -> bytes:
    binding.validate()
    payload = {
        "binding": asdict(binding), "schema": _SCHEMA, "schema_version": 1,
    }
    result = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    if len(result) > _MAX_FRAME:
        raise CredentialBrokerError("handoff request exceeds bound")
    return struct.pack("!I", len(result)) + result


def host_credential_once() -> str | None:
    """Production source. Never call this from mock or test execution."""
    if any(name != "CODEX_API_KEY" and name.upper() == "CODEX_API_KEY" for name in os.environ):
        raise CredentialBrokerError("handoff credential source is ambiguous")
    return os.environ.pop("CODEX_API_KEY", None)


class OneShotCredentialBroker:
    def __init__(
        self,
        binding: BrokerBinding,
        parent: Path,
        *,
        expected_peer_uid: int,
        credential_source: Callable[[], str | None],
    ) -> None:
        binding.validate()
        if expected_peer_uid < 0 or not parent.is_dir():
            raise CredentialBrokerError("handoff peer or parent is invalid")
        if parent.is_symlink():
            raise CredentialBrokerError("handoff parent is unsafe")
        self._binding = binding
        self._source = credential_source
        self._expected_peer_uid = expected_peer_uid
        self._directory = Path(tempfile.mkdtemp(prefix="agentguard-handoff-", dir=parent))
        os.chmod(self._directory, 0o700)
        self.socket_path = self._directory / "credential.sock"
        self._socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self._used = False
        self._socket_identity: tuple[int, int] | None = None
        try:
            self._socket.bind(str(self.socket_path))
            os.chmod(self.socket_path, 0o600)
            self._socket.listen(1)
            self._socket.settimeout(3)
            path = self.socket_path.lstat()
            self._socket_identity = (path.st_dev, path.st_ino)
            self._check_socket()
        except BaseException:
            self.close()
            raise

    def serve_once(self) -> None:
        if self._used:
            raise CredentialBrokerError("handoff has already been used")
        self._used = True
        try:
            self._binding.validate()
            self._check_socket()
            peer, _ = self._socket.accept()
            with peer:
                peer.settimeout(3)
                if _peer_uid(peer) != self._expected_peer_uid:
                    raise CredentialBrokerError("handoff peer is not approved")
                length = struct.unpack("!I", _read_exact(peer, 4))[0]
                expected = handoff_request(self._binding)
                if length == 0 or length > _MAX_FRAME or length != len(expected) - 4:
                    raise CredentialBrokerError("handoff frame is invalid")
                request = _read_exact(peer, length)
                if not hmac.compare_digest(request, expected[4:]) or peer.recv(1):
                    raise CredentialBrokerError("handoff binding is invalid")
                try:
                    value = self._source()
                except BaseException:
                    raise CredentialBrokerError("handoff credential source failed") from None
                if not isinstance(value, str) or not value.isascii():
                    raise CredentialBrokerError("handoff credential is unavailable")
                credential = bytearray(value.encode("ascii"))
                try:
                    if not _TOKEN.fullmatch(credential):
                        raise CredentialBrokerError("handoff credential is invalid")
                    peer.sendall(struct.pack("!I", len(credential)) + credential)
                finally:
                    credential[:] = b"\x00" * len(credential)
        except (OSError, ValueError, struct.error):
            raise CredentialBrokerError("handoff denied") from None
        finally:
            self.close()

    def _check_socket(self) -> None:
        path = self.socket_path.lstat()
        if (not stat.S_ISSOCK(path.st_mode)
                or (path.st_dev, path.st_ino) != self._socket_identity
                or stat.S_IMODE(path.st_mode) != 0o600):
            raise CredentialBrokerError("handoff socket was replaced")

    def close(self) -> None:
        self._socket.close()
        try:
            if self.socket_path.exists() or self.socket_path.is_symlink():
                self.socket_path.unlink()
            self._directory.rmdir()
        except OSError:
            raise CredentialBrokerError("handoff cleanup failed") from None


def _read_exact(peer: socket.socket, count: int) -> bytes:
    data = bytearray()
    while len(data) < count:
        chunk = peer.recv(count - len(data))
        if not chunk:
            raise CredentialBrokerError("handoff frame is truncated")
        data.extend(chunk)
    return bytes(data)


def _peer_uid(peer: socket.socket) -> int:
    if sys.platform.startswith("linux") and hasattr(socket, "SO_PEERCRED"):
        credentials = peer.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i"))
        _, uid, _ = struct.unpack("3i", credentials)
        return uid
    if hasattr(peer, "getpeereid"):
        uid, _ = peer.getpeereid()
        return uid
    raise CredentialBrokerError("Unix peer credentials are unavailable")
