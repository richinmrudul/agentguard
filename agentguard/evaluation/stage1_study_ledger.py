"""Crash-closed, cross-process Stage 1 token and cost reservations."""

from __future__ import annotations

import fcntl
import json
import os
import re
import secrets
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Iterator

from agentguard.evaluation.stage1_live_pricing import TokenUsage, cost_usd, worst_case_cost_usd
from agentguard.evaluation.stage1_metering import MeteringError, canonical_bytes, digest


_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
_MAX_LEDGER_BYTES = 256 * 1024
_MAX_EVENTS = 128


@dataclass(frozen=True)
class LedgerScope:
    authorization_digest: str
    plan_digest: str
    profile_digest: str
    pricing_digest: str
    redaction_digest: str
    provider: str
    model: str
    trial_ids: tuple[str, ...]
    max_trial_generations: int
    max_trial_counts: int
    max_trial_input_tokens: int
    max_trial_output_tokens: int
    max_trial_total_tokens: int
    max_trial_seconds: int
    max_trial_cost_usd: str
    max_study_cost_usd: str

    def __post_init__(self) -> None:
        for name in (
            "authorization_digest", "plan_digest", "profile_digest", "pricing_digest",
            "redaction_digest",
        ):
            if not _DIGEST.fullmatch(getattr(self, name)):
                raise MeteringError("ledger scope digest is invalid")
        if self.provider != "openai-api" or self.model != "gpt-5.2-2025-12-11":
            raise MeteringError("ledger provider or model is unsupported")
        if not self.trial_ids or len(self.trial_ids) > 16 or len(set(self.trial_ids)) != len(self.trial_ids):
            raise MeteringError("ledger trial set is missing or duplicated")
        if not all(_ID.fullmatch(value) for value in self.trial_ids):
            raise MeteringError("ledger trial ID is invalid")
        for name in (
            "max_trial_generations", "max_trial_counts", "max_trial_input_tokens",
            "max_trial_output_tokens", "max_trial_total_tokens", "max_trial_seconds",
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= 10_000_000:
                raise MeteringError("ledger limit is invalid")
        for name in ("max_trial_cost_usd", "max_study_cost_usd"):
            value = getattr(self, name)
            if not isinstance(value, str) or not re.fullmatch(r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?", value):
                raise MeteringError("ledger cost limit is invalid")
            if not 0 < Decimal(value) <= Decimal("1000000"):
                raise MeteringError("ledger cost limit is out of bounds")


class StudyLedger:
    """The journal and snapshot must agree; disagreement requires manual review.

    The directory is trusted host-side storage, never an agent mount. A local
    administrator able to roll back the entire directory is outside this format's
    crash model and requires an external monotonic anchor in Phase B2.
    """

    def __init__(self, root: Path, scope: LedgerScope) -> None:
        self.root = root
        self.scope = scope
        self._incarnation_digest = digest(secrets.token_hex(32))
        if root.is_symlink() or (root.exists() and (not root.is_dir() or root.stat().st_mode & 0o077)):
            raise MeteringError("ledger directory is not private")
        root.mkdir(mode=0o700, parents=False, exist_ok=True)
        os.chmod(root, 0o700)
        self.lock_path = root / "lock"
        self.journal_path = root / "journal.jsonl"
        self.snapshot_path = root / "snapshot.json"
        with self._locked():
            if not self.snapshot_path.exists() and not self.journal_path.exists():
                initial = self._initial_state()
                self._write_snapshot(initial)
                self._append_event({"operation": "init", "state": initial}, previous="0" * 64)
            self._read_verified()

    def _initial_state(self) -> dict[str, object]:
        return {
            "schema": "agentguard.stage1-study-ledger", "schema_version": 1,
            "scope_digest": digest(vars(self.scope)), "sequence": 0,
            "trials": {trial: {
                "counts": 0, "generations": 0, "input_tokens": 0,
                "output_tokens": 0, "charged_usd": "0", "pending": None,
                "failed": False, "request_ids": [], "started_at": None,
            } for trial in self.scope.trial_ids},
        }

    @contextmanager
    def _locked(self) -> Iterator[None]:
        flags = os.O_CREAT | os.O_RDWR
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.lock_path, flags, 0o600)
        try:
            if os.fstat(descriptor).st_mode & 0o077:
                raise MeteringError("ledger lock permissions are too broad")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

    def _read_verified(self) -> dict[str, object]:
        try:
            if self.snapshot_path.is_symlink() or self.journal_path.is_symlink():
                raise MeteringError("ledger path is a symlink")
            if self.snapshot_path.stat().st_mode & 0o077 or self.journal_path.stat().st_mode & 0o077:
                raise MeteringError("ledger file permissions are too broad")
            snapshot_raw = self.snapshot_path.read_bytes()
            journal_raw = self.journal_path.read_bytes()
            if len(snapshot_raw) > _MAX_LEDGER_BYTES or len(journal_raw) > _MAX_LEDGER_BYTES:
                raise MeteringError("ledger exceeds its bound")
            snapshot = json.loads(snapshot_raw)
            if canonical_bytes(snapshot) != snapshot_raw:
                raise MeteringError("ledger snapshot is not canonical")
            previous = "0" * 64
            last_state = None
            events = journal_raw.splitlines(keepends=True)
            if not 0 < len(events) <= _MAX_EVENTS:
                raise MeteringError("ledger audit record count is invalid")
            for index, raw in enumerate(events):
                event = json.loads(raw)
                if canonical_bytes(event) != raw or set(event) != {"previous", "entry", "hash"}:
                    raise MeteringError("ledger journal entry is not canonical")
                if event["previous"] != previous or event["hash"] != digest(event["entry"] | {"previous": previous}):
                    raise MeteringError("ledger hash chain is broken")
                previous = event["hash"]
                entry = event["entry"]
                if entry.get("operation") == "init":
                    if index or entry.get("state") != self._initial_state():
                        raise MeteringError("ledger initialization conflicts with scope")
                elif entry.get("operation") not in {"count", "reserve", "settle", "fail"}:
                    raise MeteringError("ledger operation is unknown")
                last_state = entry.get("state")
                if not isinstance(last_state, dict) or last_state.get("sequence") != index:
                    raise MeteringError("ledger sequence is missing or stale")
            if snapshot != last_state or snapshot.get("scope_digest") != digest(vars(self.scope)):
                raise MeteringError("ledger snapshot and journal conflict")
            self._check_state(snapshot)
            return snapshot
        except MeteringError:
            raise
        except (OSError, ValueError, TypeError, KeyError):
            raise MeteringError("ledger is missing, truncated, or corrupt") from None

    def _check_state(self, state: dict[str, object]) -> None:
        if set(state) != {"schema", "schema_version", "scope_digest", "sequence", "trials"}:
            raise MeteringError("ledger state has unexpected fields")
        if state["schema"] != "agentguard.stage1-study-ledger" or state["schema_version"] != 1:
            raise MeteringError("ledger schema is unsupported")
        trials = state["trials"]
        if not isinstance(trials, dict) or set(trials) != set(self.scope.trial_ids):
            raise MeteringError("ledger trial set conflicts with authorization")
        for trial in trials.values():
            if not isinstance(trial, dict) or set(trial) != {
                "counts", "generations", "input_tokens", "output_tokens",
                "charged_usd", "pending", "failed", "request_ids", "started_at",
            }:
                raise MeteringError("ledger trial record is malformed")
            if type(trial["failed"]) is not bool or not isinstance(trial["request_ids"], list):
                raise MeteringError("ledger trial status is malformed")
            if len(set(trial["request_ids"])) != len(trial["request_ids"]):
                raise MeteringError("ledger has duplicate request identities")
            if len(trial["request_ids"]) > _MAX_EVENTS or not all(
                isinstance(item, str) and _ID.fullmatch(item) for item in trial["request_ids"]
            ):
                raise MeteringError("ledger request identities are malformed")
            for name in ("counts", "generations", "input_tokens", "output_tokens"):
                if type(trial[name]) is not int or not 0 <= trial[name] <= 10_000_000:
                    raise MeteringError("ledger count is malformed")
            if not isinstance(trial["charged_usd"], str) or not re.fullmatch(
                r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?", trial["charged_usd"]
            ):
                raise MeteringError("ledger charge is malformed")
            started = trial["started_at"]
            if started is not None and (type(started) is not int or started <= 0):
                raise MeteringError("ledger trial clock is malformed")
            pending = trial["pending"]
            if pending is not None:
                if not isinstance(pending, dict) or set(pending) != {
                    "request_id", "input_tokens", "output_cap", "reserved_usd",
                    "owner_digest",
                }:
                    raise MeteringError("ledger reservation is malformed")
                if not isinstance(pending["owner_digest"], str) or not _DIGEST.fullmatch(
                    pending["owner_digest"]
                ):
                    raise MeteringError("ledger reservation owner is malformed")
                if pending["request_id"] not in trial["request_ids"]:
                    raise MeteringError("ledger reservation identity is unbound")
                for name in ("input_tokens", "output_cap"):
                    if type(pending[name]) is not int or not 0 <= pending[name] <= 10_000_000:
                        raise MeteringError("ledger reservation tokens are malformed")
                if not isinstance(pending["reserved_usd"], str) or not re.fullmatch(
                    r"(?:0|[1-9][0-9]*)(?:\.[0-9]{1,6})?", pending["reserved_usd"]
                ):
                    raise MeteringError("ledger reservation cost is malformed")

    def _write_snapshot(self, state: dict[str, object]) -> None:
        descriptor, temporary = tempfile.mkstemp(prefix=".snapshot-", dir=self.root)
        try:
            os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                target.write(canonical_bytes(state))
                target.flush()
                os.fsync(target.fileno())
            os.replace(temporary, self.snapshot_path)
            self._fsync_dir()
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def _fsync_dir(self) -> None:
        descriptor = os.open(self.root, os.O_RDONLY)
        try:
            os.fsync(descriptor)
        finally:
            os.close(descriptor)

    def _append_event(self, entry: dict[str, object], previous: str) -> None:
        event = {"previous": previous, "entry": entry, "hash": digest(entry | {"previous": previous})}
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.journal_path, flags, 0o600)
        try:
            payload = canonical_bytes(event)
            if os.fstat(descriptor).st_size + len(payload) > _MAX_LEDGER_BYTES:
                raise MeteringError("ledger audit bound reached")
            os.write(descriptor, payload)
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._fsync_dir()

    def _transition(self, state: dict[str, object], operation: str) -> None:
        journal = self.journal_path.read_bytes().splitlines()
        if len(journal) >= _MAX_EVENTS:
            raise MeteringError("ledger audit bound reached")
        previous = json.loads(journal[-1])["hash"]
        state["sequence"] += 1
        self._append_event({"operation": operation, "state": state}, previous)
        self._write_snapshot(state)

    def _trial(self, state: dict[str, object], trial_id: str) -> dict[str, object]:
        trials = state["trials"]
        if trial_id not in trials or any(item["failed"] or item["pending"] for item in trials.values()):
            raise MeteringError("trial is unknown or study has an uncertain request")
        return trials[trial_id]

    def _identity(self, trial: dict[str, object], request_id: str) -> None:
        if not _ID.fullmatch(request_id) or request_id in trial["request_ids"]:
            raise MeteringError("request identity is invalid or replayed")

    def _deadline(self, trial: dict[str, object]) -> None:
        started = trial["started_at"]
        now = int(time.time())
        if started is None:
            trial["started_at"] = now
        elif now < started or now - started >= self.scope.max_trial_seconds:
            raise MeteringError("durable trial elapsed-time limit reached")

    def count(self, trial_id: str, request_id: str) -> None:
        with self._locked():
            state = self._read_verified()
            trial = self._trial(state, trial_id)
            self._identity(trial, request_id)
            self._deadline(trial)
            if trial["counts"] >= self.scope.max_trial_counts:
                raise MeteringError("trial count-request limit reached")
            trial["counts"] += 1
            trial["request_ids"].append(request_id)
            self._transition(state, "count")

    def reserve(self, trial_id: str, request_id: str, counted_input: int, output_cap: int) -> Decimal:
        amount = worst_case_cost_usd(counted_input, output_cap)
        with self._locked():
            state = self._read_verified()
            trial = self._trial(state, trial_id)
            self._identity(trial, request_id)
            self._deadline(trial)
            if trial["generations"] >= self.scope.max_trial_generations:
                raise MeteringError("trial generation limit reached")
            if trial["input_tokens"] + counted_input > self.scope.max_trial_input_tokens:
                raise MeteringError("trial input-token limit reached")
            if trial["output_tokens"] + output_cap > self.scope.max_trial_output_tokens:
                raise MeteringError("trial output-token limit reached")
            if trial["input_tokens"] + trial["output_tokens"] + counted_input + output_cap > self.scope.max_trial_total_tokens:
                raise MeteringError("trial total-token limit reached")
            if Decimal(trial["charged_usd"]) + amount > Decimal(self.scope.max_trial_cost_usd):
                raise MeteringError("trial cost reservation exceeded")
            total = sum(Decimal(item["charged_usd"]) for item in state["trials"].values())
            if total + amount > Decimal(self.scope.max_study_cost_usd):
                raise MeteringError("study cost reservation exceeded")
            trial["generations"] += 1
            trial["request_ids"].append(request_id)
            trial["charged_usd"] = str(Decimal(trial["charged_usd"]) + amount)
            trial["pending"] = {"request_id": request_id, "input_tokens": counted_input,
                                "output_cap": output_cap, "reserved_usd": str(amount),
                                "owner_digest": self._incarnation_digest}
            self._transition(state, "reserve")
        return amount

    def settle(self, trial_id: str, request_id: str, usage: TokenUsage) -> None:
        with self._locked():
            state = self._read_verified()
            trial = state["trials"].get(trial_id)
            if not isinstance(trial, dict) or trial["failed"]:
                raise MeteringError("trial is failed or unknown")
            pending = trial["pending"]
            if not isinstance(pending, dict) or pending["request_id"] != request_id:
                raise MeteringError("terminal usage does not bind to reservation")
            if pending["owner_digest"] != self._incarnation_digest:
                raise MeteringError("restarted process cannot settle an uncertain reservation")
            if usage.input_tokens != pending["input_tokens"] or usage.output_tokens > pending["output_cap"]:
                raise MeteringError("terminal usage exceeds or differs from reservation")
            actual = cost_usd(usage)
            reserved = Decimal(pending["reserved_usd"])
            if actual > reserved:
                raise MeteringError("actual cost exceeds worst-case reservation")
            trial["charged_usd"] = str(Decimal(trial["charged_usd"]) - reserved + actual)
            trial["input_tokens"] += usage.input_tokens
            trial["output_tokens"] += usage.output_tokens
            trial["pending"] = None
            self._transition(state, "settle")

    def fail(self, trial_id: str) -> None:
        with self._locked():
            state = self._read_verified()
            trial = state["trials"].get(trial_id)
            if not isinstance(trial, dict) or trial["failed"]:
                raise MeteringError("trial is failed or unknown")
            trial["failed"] = True
            self._transition(state, "fail")

    def snapshot(self) -> dict[str, object]:
        with self._locked():
            return self._read_verified()
