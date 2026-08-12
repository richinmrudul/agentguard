from dataclasses import dataclass
import os
import select
import subprocess
import threading
import time
from typing import BinaryIO, Optional


@dataclass(frozen=True)
class LimitedOutput:
    text: str
    truncated: bool


class BoundedTailBuffer:
    def __init__(self, max_bytes: int) -> None:
        if max_bytes <= 0:
            raise ValueError("max_bytes must be positive.")
        self.max_bytes = max_bytes
        self.total_bytes = 0
        self.peak_retained_bytes = 0
        self._tail = bytearray()

    def append(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        if len(chunk) >= self.max_bytes:
            self._tail[:] = chunk[-self.max_bytes :]
        else:
            overflow = len(self._tail) - self.max_bytes
            overflow += len(chunk)
            if overflow > 0:
                del self._tail[:overflow]
            self._tail.extend(chunk)
        self.peak_retained_bytes = max(self.peak_retained_bytes, len(self._tail))

    def output(self) -> LimitedOutput:
        if self.total_bytes <= self.max_bytes:
            return LimitedOutput(
                text=bytes(self._tail).decode("utf-8", errors="replace"),
                truncated=False,
            )
        return _limit_encoded_output(bytes(self._tail), self.max_bytes)


class BoundedHeadBuffer(BoundedTailBuffer):
    def append(self, chunk: bytes) -> None:
        self.total_bytes += len(chunk)
        remaining = self.max_bytes - len(self._tail)
        if remaining > 0:
            self._tail.extend(chunk[:remaining])
        self.peak_retained_bytes = max(self.peak_retained_bytes, len(self._tail))

    def output(self) -> LimitedOutput:
        return LimitedOutput(
            text=bytes(self._tail).decode("utf-8", errors="replace"),
            truncated=self.total_bytes > self.max_bytes,
        )


@dataclass(frozen=True)
class ProcessOutput:
    stdout: LimitedOutput
    stderr: LimitedOutput


class BoundedProcessOutput:
    def __init__(
        self,
        process: subprocess.Popen,
        max_bytes: int,
        *,
        retain_tail: bool = True,
    ) -> None:
        if process.stdout is None or process.stderr is None:
            raise ValueError("Process stdout and stderr must be piped.")
        self.process = process
        buffer_type = BoundedTailBuffer if retain_tail else BoundedHeadBuffer
        self.stdout_buffer = buffer_type(max_bytes)
        self.stderr_buffer = buffer_type(max_bytes)
        self._stop_event = threading.Event()
        self._threads = [
            threading.Thread(
                target=self._drain,
                args=(process.stdout, self.stdout_buffer),
                daemon=True,
            ),
            threading.Thread(
                target=self._drain,
                args=(process.stderr, self.stderr_buffer),
                daemon=True,
            ),
        ]
        for thread in self._threads:
            thread.start()

    def _drain(self, stream: BinaryIO, buffer: BoundedTailBuffer) -> None:
        if os.name == "posix":
            try:
                descriptor = stream.fileno()
            except (OSError, ValueError):
                pass
            else:
                self._drain_posix(stream, descriptor, buffer)
                return
        try:
            while True:
                if self._stop_event.is_set():
                    return
                chunk = stream.read(65536)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                buffer.append(chunk)
        finally:
            stream.close()

    def _drain_posix(
        self,
        stream: BinaryIO,
        descriptor: int,
        buffer: BoundedTailBuffer,
    ) -> None:
        try:
            while not self._stop_event.is_set():
                readable, _, _ = select.select([descriptor], [], [], 0.05)
                if not readable:
                    continue
                chunk = os.read(descriptor, 65536)
                if not chunk:
                    return
                buffer.append(chunk)
        except (OSError, ValueError):
            return
        finally:
            stream.close()

    def wait(self, timeout: Optional[float] = None) -> int:
        return self.process.wait(timeout=timeout)

    def finish(self, timeout: Optional[float] = None) -> ProcessOutput:
        deadline = None if timeout is None else time.monotonic() + max(0.0, timeout)
        for thread in self._threads:
            remaining = None
            if deadline is not None:
                remaining = max(0.0, deadline - time.monotonic())
            thread.join(timeout=remaining)
        if deadline is not None and any(thread.is_alive() for thread in self._threads):
            self._stop_event.set()
            if os.name != "posix":
                self._close_streams()
            for thread in self._threads:
                thread.join(timeout=0.1)
            if os.name != "posix":
                for stream in (self.process.stdout, self.process.stderr):
                    if stream is not None and not stream.closed:
                        try:
                            stream.close()
                        except OSError:
                            pass
        return ProcessOutput(
            stdout=self.stdout_buffer.output(),
            stderr=self.stderr_buffer.output(),
        )

    def _close_streams(self) -> None:
        for stream in (self.process.stdout, self.process.stderr):
            if stream is None or stream.closed:
                continue
            try:
                os.close(stream.fileno())
            except OSError:
                pass


def _limit_encoded_output(encoded: bytes, max_bytes: int) -> LimitedOutput:
    marker = f"[agentguard] Output truncated to last {max_bytes} bytes.\n"
    marker_bytes = marker.encode("utf-8")
    if len(marker_bytes) >= max_bytes:
        return LimitedOutput(
            text=marker_bytes[:max_bytes].decode("utf-8", errors="replace"),
            truncated=True,
        )

    suffix_size = max_bytes - len(marker_bytes)
    suffix_bytes = encoded[-suffix_size:]
    while True:
        suffix = suffix_bytes.decode("utf-8", errors="replace")
        overage = len(marker_bytes) + len(suffix.encode("utf-8")) - max_bytes
        if overage <= 0:
            break
        suffix_bytes = suffix_bytes[max(1, overage) :]
    return LimitedOutput(
        text=marker + suffix,
        truncated=True,
    )


def limit_output(text: str, max_bytes: int) -> LimitedOutput:
    encoded = text.encode("utf-8")
    if len(encoded) <= max_bytes:
        return LimitedOutput(text=text, truncated=False)
    return _limit_encoded_output(encoded, max_bytes)
