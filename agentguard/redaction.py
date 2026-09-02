import re
from typing import Optional


REDACTION_MARKER = "[REDACTED]"
SECRET_OPTION_NAMES = {
    "--token",
    "--api-key",
    "--apikey",
    "--password",
    "--passwd",
    "--client-secret",
    "--access-token",
    "--auth-token",
}
SECRET_KEY_PATTERN = re.compile(
    r"(TOKEN|SECRET|PASSWORD|KEY|CREDENTIAL|AUTH|COOKIE)",
    re.IGNORECASE,
)
URL_CREDENTIALS_PATTERN = re.compile(
    r"(?P<scheme>[a-z][a-z0-9+.-]*://)[^\s/@]+@",
    re.IGNORECASE,
)
AUTHORIZATION_PATTERN = re.compile(
    r"(?i)\b(authorization\s*:\s*)(?:basic|bearer)\s+\S+"
)
KEYED_CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(password|passwd|secret|token|api[_-]?key|access[_-]?key|"
    r"client[_-]?secret|auth[_-]?token|credential)"
    r"(\s*[:=]\s*)[^\s,;]+"
)
OPTION_VALUE_PATTERN = re.compile(
    r"(?i)(?<!\S)(--(?:token|api-key|apikey|password|passwd|client-secret|"
    r"access-token|auth-token))(\s+)([^\s,;]+)"
)
OPTION_EQUALS_PATTERN = re.compile(
    r"(?i)(?<!\S)(--(?:token|api-key|apikey|password|passwd|client-secret|"
    r"access-token|auth-token)=)([^\s,;]+)"
)
TOKEN_SHAPE_PATTERNS = [
    re.compile(r"\b(?:sk|ghp|github_pat)_[A-Za-z0-9_=-]{8,}\b"),
    re.compile(r"AGENTGUARD_SECRET_CANARY[_A-Z0-9-]*", re.IGNORECASE),
]


def redact_credentials(
    value: object,
    sensitive_values: Optional[list[str]] = None,
    *,
    marker: str = REDACTION_MARKER,
) -> str:
    text = "" if value is None else str(value)
    text = URL_CREDENTIALS_PATTERN.sub(rf"\g<scheme>{marker}@", text)
    text = AUTHORIZATION_PATTERN.sub(rf"\1{marker}", text)
    text = KEYED_CREDENTIAL_PATTERN.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{marker}",
        text,
    )
    text = OPTION_EQUALS_PATTERN.sub(rf"\1{marker}", text)
    text = OPTION_VALUE_PATTERN.sub(rf"\1\2{marker}", text)
    for pattern in TOKEN_SHAPE_PATTERNS:
        text = pattern.sub(marker, text)
    for secret in sensitive_values or []:
        text = text.replace(secret, marker)
    return text


def redact_credential_arguments(
    command: list[str],
    sensitive_values: Optional[list[str]] = None,
    *,
    marker: str = REDACTION_MARKER,
) -> list[str]:
    sanitized: list[str] = []
    redact_next = False
    header_next = False
    for argument in command:
        lowered = argument.lower()
        if redact_next:
            sanitized.append(marker)
            redact_next = False
            continue
        if header_next:
            sanitized.append(redact_credentials(argument, sensitive_values, marker=marker))
            header_next = False
            continue
        if lowered in SECRET_OPTION_NAMES:
            sanitized.append(argument)
            redact_next = True
            continue
        if any(lowered.startswith(f"{option}=") for option in SECRET_OPTION_NAMES):
            sanitized.append(f"{argument.split('=', 1)[0]}={marker}")
            continue
        if lowered in {"-h", "--header"}:
            sanitized.append(argument)
            header_next = True
            continue
        sanitized.append(redact_credentials(argument, sensitive_values, marker=marker))
    return sanitized
