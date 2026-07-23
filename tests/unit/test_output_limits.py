import subprocess
import sys

from agentguard.instrumentation.output_limits import (
    BoundedProcessOutput,
    BoundedTailBuffer,
)


def test_tail_buffer_retains_at_most_configured_bytes() -> None:
    buffer = BoundedTailBuffer(1024)

    for _ in range(64):
        buffer.append(b"x" * 65536)
    buffer.append(b"TAIL")

    output = buffer.output()
    assert buffer.total_bytes > 4_000_000
    assert buffer.peak_retained_bytes <= 1024
    assert output.truncated is True
    assert len(output.text.encode("utf-8")) <= 1024
    assert output.text.startswith("[agentguard] Output truncated")
    assert output.text.endswith("TAIL")


def test_tail_buffer_replaces_invalid_utf8_within_byte_limit() -> None:
    buffer = BoundedTailBuffer(80)

    buffer.append(b"x" * 1000 + b"\xffTAIL")

    output = buffer.output()
    assert output.truncated is True
    assert "\ufffdTAIL" in output.text
    assert len(output.text.encode("utf-8")) <= 80


def test_process_output_drains_stdout_and_stderr_concurrently() -> None:
    script = (
        "import sys, threading\n"
        "def write(stream, byte, end):\n"
        "    for _ in range(32):\n"
        "        stream.write(byte * 65536)\n"
        "        stream.flush()\n"
        "    stream.write(end)\n"
        "threads = [\n"
        "    threading.Thread(target=write, "
        "args=(sys.stdout.buffer, b'o', b'STDOUT_END')),\n"
        "    threading.Thread(target=write, "
        "args=(sys.stderr.buffer, b'e', b'STDERR_END')),\n"
        "]\n"
        "[thread.start() for thread in threads]\n"
        "[thread.join() for thread in threads]\n"
    )
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    capture = BoundedProcessOutput(process, 1024)

    assert capture.wait(timeout=10) == 0
    output = capture.finish()

    assert capture.stdout_buffer.total_bytes > 2_000_000
    assert capture.stderr_buffer.total_bytes > 2_000_000
    assert capture.stdout_buffer.peak_retained_bytes <= 1024
    assert capture.stderr_buffer.peak_retained_bytes <= 1024
    assert output.stdout.truncated is True
    assert output.stderr.truncated is True
    assert output.stdout.text.endswith("STDOUT_END")
    assert output.stderr.text.endswith("STDERR_END")
