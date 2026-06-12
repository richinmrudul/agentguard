from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from dataclasses import dataclass
from typing import Callable, Generic, TypeVar


ItemT = TypeVar("ItemT")
ResultT = TypeVar("ResultT")


@dataclass(frozen=True)
class BoundedScheduleResult(Generic[ResultT]):
    results: list[ResultT]
    submitted: int
    executed: int
    stopped_early: bool


def run_bounded_schedule(
    items: list[ItemT],
    *,
    workers: int,
    fail_fast: bool,
    runner: Callable[[ItemT], ResultT],
    is_failure: Callable[[ResultT], bool],
) -> BoundedScheduleResult[ResultT]:
    if isinstance(workers, bool) or not isinstance(workers, int) or workers <= 0:
        raise ValueError("Scheduler workers must be a positive integer.")
    if not items:
        return BoundedScheduleResult([], 0, 0, False)
    effective_workers = min(workers, len(items))
    if effective_workers == 1:
        results = []
        for item in items:
            result = runner(item)
            results.append(result)
            if fail_fast and is_failure(result):
                break
        executed = len(results)
        return BoundedScheduleResult(
            results=results,
            submitted=executed,
            executed=executed,
            stopped_early=executed < len(items),
        )

    results_by_index: dict[int, ResultT] = {}
    next_index = 0
    stopped_early = False
    executor = ThreadPoolExecutor(max_workers=effective_workers)
    futures: dict[Future[ResultT], int] = {}

    def submit_next() -> bool:
        nonlocal next_index
        if next_index >= len(items):
            return False
        future = executor.submit(runner, items[next_index])
        futures[future] = next_index
        next_index += 1
        return True

    try:
        for _ in range(effective_workers):
            submit_next()
        while futures:
            if fail_fast:
                completed, _ = wait(futures)
            else:
                completed, _ = wait(futures, return_when=FIRST_COMPLETED)
            for future in sorted(completed, key=lambda item: futures[item]):
                index = futures.pop(future)
                result = future.result()
                results_by_index[index] = result
                if fail_fast and is_failure(result):
                    stopped_early = next_index < len(items)
            if stopped_early:
                continue
            while len(futures) < effective_workers and submit_next():
                pass
    except BaseException:
        executor.shutdown(wait=True, cancel_futures=True)
        raise
    else:
        executor.shutdown(wait=True)

    results = [
        results_by_index[index] for index in sorted(results_by_index)
    ]
    return BoundedScheduleResult(
        results=results,
        submitted=next_index,
        executed=len(results),
        stopped_early=stopped_early,
    )
