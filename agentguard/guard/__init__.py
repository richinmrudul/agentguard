from agentguard.guard.command import (
    CommandGuardSummary,
    CommandGuardViolation,
    RuntimeCommandGuard,
)
from agentguard.guard.filesystem import (
    GuardMode,
    LiveGuardSummary,
    LiveGuardViolation,
    ProcessController,
    RuntimeFilesystemGuard,
)
__all__ = [
    "CommandGuardSummary",
    "CommandGuardViolation",
    "GuardIncident",
    "GuardIncidentPaths",
    "GuardIncidentViolation",
    "GuardMetrics",
    "GuardMode",
    "LiveGuardSummary",
    "LiveGuardViolation",
    "ProcessController",
    "RuntimeCommandGuard",
    "RuntimeFilesystemGuard",
    "build_guard_incident",
    "guard_metrics",
    "incident_summary",
    "write_guard_incident",
]


def __getattr__(name: str):
    if name in {
        "GuardIncident",
        "GuardIncidentPaths",
        "GuardIncidentViolation",
        "GuardMetrics",
        "build_guard_incident",
        "guard_metrics",
        "incident_summary",
        "write_guard_incident",
    }:
        from agentguard.guard import incident

        return getattr(incident, name)
    raise AttributeError(name)
