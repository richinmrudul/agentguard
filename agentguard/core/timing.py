import time
from contextlib import contextmanager
from typing import Callable, Iterator, Optional


class StageTimingRecorder:
    def __init__(self, clock: Optional[Callable[[], float]] = None) -> None:
        self._clock = clock or time.perf_counter
        self._total_started: Optional[float] = None
        self.stages: dict[str, float] = {}
        self.total_seconds = 0.0

    def start_total(self) -> None:
        self._total_started = self._clock()

    def finish_total(self) -> None:
        if self._total_started is None:
            raise RuntimeError("Stage timing total was not started.")
        self.total_seconds = self._clock() - self._total_started

    def now(self) -> float:
        return self._clock()

    @contextmanager
    def measure(self, stage: str) -> Iterator[None]:
        started = self._clock()
        try:
            yield
        finally:
            self.stages[stage] = self.stages.get(stage, 0.0) + (
                self._clock() - started
            )
