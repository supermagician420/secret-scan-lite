#!/usr/bin/env python3
"""A small, dependency-free secret scanner with masks and explicit limits."""

import argparse
import fnmatch
import json
import math
import re
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Pattern, Sequence, Set, Tuple


class ScanError(ValueError):
    """The scan input is invalid."""


@dataclass(frozen=True)
class Rule:
    name: str
    pattern: Pattern[str]
    severity: str


@dataclass(frozen=True)
class Finding:
    path: str
    line: int
    kind: str
    severity: str
    preview: str


@dataclass(frozen=True)
class ScanResult:
    files_scanned: int
    files_skipped: int
    findings: Tuple[Finding, ...]


_RULES: Tuple[Rule, ...] = (
    Rule(
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
        "high",
    ),
    Rule("aws-access-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "high"),
    Rule("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b"), "high"),
    Rule("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "high"),
    Rule("google-api-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "high"),
    Rule(
        "connection-string",
        re.compile(r"\b(?:postgres|postgresql|mysql|mongodb)://[^\s:/]+:[^\s@]+@[^\s]+", re.IGNORECASE),
        "high",
    ),
    Rule(
        "generic-secret",
        re.compile(
            r"(?i)\b(?:api[_-]?key|secret|token|password|passwd|client[_-]?secret)\b"
            r"\s*[:=]\s*[\"']?(?P<value>[A-Za-z0-9_\-./+=]{12,})"
        ),
        "high",
    ),
)

_ENTROPY_RE = re.compile(r"[A-Za-z0-9+/=_-]{24,}")
_PLACEHOLDERS = ("example", "sample", "dummy", "placeholder", "not-a-real", "xxxx", "changeme", "your_")
_SKIP_DIRS = {".git", "__pycache__", "node_modules", "vendor", ".venv", "venv", "dist", "build"}
_SKIP_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".pdf", ".zip", ".gz", ".tar",
    ".exe", ".dll", ".so", ".dylib", ".class", ".jar", ".woff", ".woff2", ".ttf",
}


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return value[:4] + "*" * min(12, len(value) - 8) + value[-4:]


def _is_placeholder(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _PLACEHOLDERS)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts: Dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _entropy_findings(path: str, line_number: int, line: str) -> List[Finding]:
    findings: List[Finding] = []
    for match in _ENTROPY_RE.finditer(line):
        candidate = match.group(0)
        if candidate.isdigit() or candidate.isalpha():
            continue
        if not any(char.isdigit() for char in candidate) or not any(char.isalpha() for char in candidate):
            continue
        if _is_placeholder(candidate):
            continue
        if shannon_entropy(candidate) < 4.5:
            continue
        preview = line.replace(candidate, _mask(candidate))
        findings.append(Finding(path, line_number, "high-entropy-string", "medium", preview))
    return findings


def scan_text(text: str, path: str = "<memory>", entropy: bool = True) -> Tuple[Finding, ...]:
    findings: List[Finding] = []
    seen: Set[Tuple[int, str, str]] = set()
    for line_number, line in enumerate(text.splitlines(), 1):
        if "pragma: allowlist secret" in line:
            continue
        for rule in _RULES:
            for match in rule.pattern.finditer(line):
                matched = match.group(0)
                secret = match.groupdict().get("value") or matched
                if _is_placeholder(secret):
                    continue
                key = (line_number, rule.name, secret)
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(path, line_number, rule.name, rule.severity, line.replace(secret, _mask(secret)))
                )
        if entropy:
            for finding in _entropy_findings(path, line_number, line):
                key = (finding.line, finding.kind, finding.preview)
                if key not in seen:
                    seen.add(key)
                    findings.append(finding)
    return tuple(findings)


def _matches_exclude(path: Path, root: Path, patterns: Sequence[str]) -> bool:
    relative = path.relative_to(root).as_posix() if path != root else path.name
    return any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(path.name, pattern) for pattern in patterns)


def scan_path(path: str, includes: Sequence[str] = (), excludes: Sequence[str] = (), entropy: bool = True, max_bytes: int = 1_000_000) -> ScanResult:
    target = Path(path)
    if not target.exists():
        raise ScanError("path does not exist: %s" % path)
    if target.is_file():
        candidates = [target]
        root = target.parent
    elif target.is_dir():
        candidates = sorted(item for item in target.rglob("*") if item.is_file())
        root = target
    else:
        raise ScanError("path is not a regular file or directory: %s" % path)

    findings: List[Finding] = []
    scanned = 0
    skipped = 0
    for candidate in candidates:
        relative = candidate.relative_to(root).as_posix() if candidate != root else candidate.name
        if any(part in _SKIP_DIRS for part in candidate.parts):
            skipped += 1
            continue
        if candidate.suffix.lower() in _SKIP_EXTENSIONS:
            skipped += 1
            continue
        if _matches_exclude(candidate, root, excludes):
            skipped += 1
            continue
        if includes and not any(fnmatch.fnmatch(relative, pattern) or fnmatch.fnmatch(candidate.name, pattern) for pattern in includes):
            skipped += 1
            continue
        try:
            if candidate.stat().st_size > max_bytes:
                skipped += 1
                continue
            data = candidate.read_bytes()
        except OSError:
            skipped += 1
            continue
        if b"\x00" in data:
            skipped += 1
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            skipped += 1
            continue
        scanned += 1
        findings.extend(scan_text(text, relative, entropy=entropy))
    return ScanResult(scanned, skipped, tuple(sorted(findings, key=lambda item: (item.path, item.line, item.kind))))


def render_text(result: ScanResult) -> str:
    lines = ["Scanned %d files, skipped %d." % (result.files_scanned, result.files_skipped)]
    if not result.findings:
        lines.append("No potential secrets found.")
        return "\n".join(lines) + "\n"
    lines.append("Found %d potential secret(s):" % len(result.findings))
    for finding in result.findings:
        lines.append(
            "- [%s] %s:%d (%s): %s"
            % (finding.severity.upper(), finding.path, finding.line, finding.kind, finding.preview)
        )
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    return json.dumps(asdict(result), ensure_ascii=False, indent=2)


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Scan files for common secret patterns")
    parser.add_argument("path", nargs="?", default=".", help="file or directory to scan (default: .)")
    parser.add_argument("--include", action="append", default=[], help="glob of files to include; repeatable")
    parser.add_argument("--exclude", action="append", default=[], help="glob of files to exclude; repeatable")
    parser.add_argument("--no-entropy", action="store_true", help="disable high-entropy string detection")
    parser.add_argument("--max-bytes", type=int, default=1_000_000, help="skip files larger than this")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    if args.max_bytes <= 0:
        print("error: --max-bytes must be positive", file=sys.stderr)
        return 2
    try:
        result = scan_path(
            args.path,
            includes=args.include,
            excludes=args.exclude,
            entropy=not args.no_entropy,
            max_bytes=args.max_bytes,
        )
    except ScanError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2
    except OSError as exc:
        print("error: %s" % exc, file=sys.stderr)
        return 2

    print(render_json(result) if args.json else render_text(result), end="")
    return 1 if result.findings else 0


if __name__ == "__main__":
    raise SystemExit(main())
