from dataclasses import dataclass
import subprocess
import threading
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

    @staticmethod
    def _drain(stream: BinaryIO, buffer: BoundedTailBuffer) -> None:
        try:
            while True:
                chunk = stream.read(65536)
                if not chunk:
                    return
                if isinstance(chunk, str):
                    chunk = chunk.encode("utf-8")
                buffer.append(chunk)
        finally:
            stream.close()

    def wait(self, timeout: Optional[float] = None) -> int:
        return self.process.wait(timeout=timeout)

    def finish(self) -> ProcessOutput:
        for thread in self._threads:
            thread.join()
        return ProcessOutput(
            stdout=self.stdout_buffer.output(),
            stderr=self.stderr_buffer.output(),
        )


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
