from dataclasses import dataclass, field
from typing import Any, Optional


@dataclass(frozen=True)
class TimelineEvent:
    order: int
    event_type: str
    message: str
    metadata: dict[str, Any] = field(default_factory=dict)


class TimelineRecorder:
    def __init__(self) -> None:
        self._events: list[TimelineEvent] = []

    def add(
        self,
        event_type: str,
        message: str,
        metadata: Optional[dict[str, Any]] = None,
    ) -> TimelineEvent:
        event = TimelineEvent(
            order=len(self._events) + 1,
            event_type=event_type,
            message=message,
            metadata=metadata or {},
        )
        self._events.append(event)
        return event

    @property
    def events(self) -> list[TimelineEvent]:
        return list(self._events)
