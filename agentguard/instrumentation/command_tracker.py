from dataclasses import dataclass, field


@dataclass
class CommandTracker:
    commands: list[str] = field(default_factory=list)

    def record(self, command: str) -> None:
        self.commands.append(command)
