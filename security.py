"""
security.py — CloudShield WAF threat analysis engine.

analyze_payload(payload) -> (is_safe: bool, message: str, threats: list[str], risk_score: int)
"""

import re
from dataclasses import dataclass, field
from typing import List, Tuple

# ── Threat rule definitions ───────────────────────────────────────────────────

@dataclass
class ThreatRule:
    name: str           # Short label shown in UI tags
    pattern: re.Pattern
    description: str
    severity: int       # 1-10; rules with severity >= BLOCK_THRESHOLD cause a block

BLOCK_THRESHOLD = 5     # Minimum severity to block the request

RULES: List[ThreatRule] = [
    # SQL Injection
    ThreatRule(
        name="SQLi",
        pattern=re.compile(
            r"(\b(select|insert|update|delete|drop|create|alter|truncate|exec|union|from|where|having|order\s+by|group\s+by)\b"
            r"|\b(or|and)\s+[\w'\"]+\s*=\s*[\w'\"]+"
            r"|--|;.*--"
            r"|'\s*(or|and)\s+'",
            re.IGNORECASE,
        ),
        description="SQL Injection pattern detected",
        severity=9,
    ),
    # XSS
    ThreatRule(
        name="XSS",
        pattern=re.compile(
            r"(<\s*script[\s\S]*?>|<\s*/\s*script\s*>"
            r"|javascript\s*:"
            r"|on\w+\s*=\s*['\"]"
            r"|<\s*iframe"
            r"|<\s*img[^>]+onerror"
            r"|eval\s*\("
            r"|document\.(cookie|write|location))",
            re.IGNORECASE,
        ),
        description="Cross-Site Scripting (XSS) pattern detected",
        severity=9,
    ),
    # Path Traversal
    ThreatRule(
        name="PathTraversal",
        pattern=re.compile(
            r"(\.\./|\.\.\\|%2e%2e%2f|%252e%252e%252f|/etc/passwd|/etc/shadow|/proc/self)",
            re.IGNORECASE,
        ),
        description="Path traversal / directory traversal detected",
        severity=8,
    ),
    # Command Injection
    ThreatRule(
        name="CmdInjection",
        pattern=re.compile(
            r"(;\s*(ls|cat|rm|wget|curl|bash|sh|python|perl|ruby|nc|netcat|nmap|ping)\b"
            r"|\|\s*(bash|sh|cmd)"
            r"|`[^`]+`"
            r"|\$\([^)]+\))",
            re.IGNORECASE,
        ),
        description="Command injection pattern detected",
        severity=10,
    ),
    # SSRF
    ThreatRule(
        name="SSRF",
        pattern=re.compile(
            r"(https?://(localhost|127\.0\.0\.1|0\.0\.0\.0|169\.254\.|10\.\d+\.\d+\.\d+|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)"
            r"|file://"
            r"|gopher://"
            r"|dict://)",
            re.IGNORECASE,
        ),
        description="Server-Side Request Forgery (SSRF) indicator",
        severity=8,
    ),
    # XXE
    ThreatRule(
        name="XXE",
        pattern=re.compile(
            r"(<!ENTITY|SYSTEM\s+['\"]|<!DOCTYPE[^>]+\[)",
            re.IGNORECASE,
        ),
        description="XML External Entity (XXE) injection pattern",
        severity=8,
    ),
    # Prototype Pollution
    ThreatRule(
        name="ProtoPollution",
        pattern=re.compile(
            r"(__proto__|constructor\.prototype|Object\.prototype)",
            re.IGNORECASE,
        ),
        description="Prototype pollution attempt detected",
        severity=7,
    ),
    # Null byte
    ThreatRule(
        name="NullByte",
        pattern=re.compile(r"(%00|\x00)", re.IGNORECASE),
        description="Null byte injection detected",
        severity=7,
    ),
    # Suspicious encoding
    ThreatRule(
        name="EncodingAbuse",
        pattern=re.compile(r"(%[0-9a-f]{2}){4,}", re.IGNORECASE),
        description="Suspicious URL encoding sequence",
        severity=4,
    ),
    # Long payload (potential buffer overflow probe)
    ThreatRule(
        name="LongPayload",
        pattern=re.compile(r".{1001,}", re.DOTALL),
        description="Payload exceeds maximum allowed length",
        severity=5,
    ),
]

# Whitelist: very simple safe strings skip analysis entirely
_SAFE_WHITELIST = re.compile(r"^[a-zA-Z0-9 ,.\-_!?'\"]{1,200}$")


def analyze_payload(payload: str) -> Tuple[bool, str, List[str], int]:
    """
    Analyse a WAF payload.

    Returns:
        is_safe    — True if the payload should be allowed through
        message    — Human-readable verdict sentence
        threats    — List of matched threat-category names
        risk_score — 0-100 numeric risk score
    """
    if not payload:
        return True, "Empty payload — nothing to analyse.", [], 0

    matched_threats: List[str] = []
    total_severity = 0
    messages: List[str] = []

    for rule in RULES:
        if rule.pattern.search(payload):
            matched_threats.append(rule.name)
            total_severity += rule.severity
            messages.append(rule.description)

    # Risk score: clamp to 0-100
    risk_score = min(100, total_severity * 8)

    # A single rule at or above BLOCK_THRESHOLD is enough to block
    blocking_severities = [
        r.severity for r in RULES
        if r.name in matched_threats and r.severity >= BLOCK_THRESHOLD
    ]

    if blocking_severities:
        primary = messages[0] if messages else "Threat detected"
        return (
            False,
            f"{primary} ({', '.join(matched_threats)})",
            matched_threats,
            risk_score,
        )

    if matched_threats:
        # Low-severity matches — flag but allow
        return (
            True,
            f"Low-risk pattern noted ({', '.join(matched_threats)}). Allowed with caution.",
            matched_threats,
            risk_score,
        )

    return True, "No threats detected.", [], 0
