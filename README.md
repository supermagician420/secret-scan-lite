# secret-scan-lite

A small, dependency-free secret scanner for local pre-commit checks and learning.

It is deliberately not a replacement for [gitleaks](https://github.com/gitleaks/gitleaks) or [trufflehog](https://github.com/trufflesecurity/trufflehog). It is a readable, ~300-line scanner with explicit rules, masked output, and honest limits.

## Quick start

Requires Python 3.8+, no third-party packages.

```bash
python secret_scan_lite.py examples/leaky.py --no-entropy
```

Exit code `1` means something matched:

```text
Scanned 1 files, skipped 0.
Found 1 potential secret(s):
- [HIGH] leaky.py:1 (aws-access-key): aws_key = "AKIA************LKEY"
```

Scan a clean file (exit `0`):

```bash
python secret_scan_lite.py examples/clean.py
```

Scan a directory, with JSON and excludes:

```bash
python secret_scan_lite.py . --exclude "tests/*" --exclude "*.lock" --json
```

## Rules

| Rule | Severity | Example shape |
| --- | --- | --- |
| `private-key` | high | `-----BEGIN RSA PRIVATE KEY-----` |
| `aws-access-key` | high | `AKIA` + 16 uppercase alphanumerics |
| `github-token` | high | `ghp_` + 36+ characters |
| `slack-token` | high | `xoxb-...` |
| `google-api-key` | high | `AIza` + 35 characters |
| `connection-string` | high | `postgres://user:password@host/db` |
| `generic-secret` | high | `api_key = "..."`, `password: "..."` |
| `high-entropy-string` | medium | Long random-looking token (opt-out with `--no-entropy`) |

## Masking and allowlisting

Reports never print the full match. Values are shortened to a prefix, a fixed number of `*`, and a suffix.

To allow a known false positive on a line:

```python
api_key = "Zx9Qw2Er4Ty6Ui8Op0"  # pragma: allowlist secret
```

Placeholder-looking values containing `example`, `sample`, `dummy`, `placeholder`, `not-a-real`, `xxxx`, `changeme`, or `your_` are ignored.

## Design choices

- **Rules are visible.** No opaque ML model; you can read and edit every pattern.
- **Masked by default.** A scanner should not become a second leak.
- **Binary and large files skipped.** Text only, with a configurable size ceiling.
- **Entropy is a signal, not proof.** Random strings can be hashes, IDs, or test data.
- **Exit code is useful.** `1` for findings, `0` for clean, `2` for errors.

## Limitations

- Regexes miss context-specific secrets and many token formats.
- Entropy detection produces false positives (hashes, UUIDs, generated fixtures).
- There is no verification against a provider, no git-history scan, and no baseline suppression.
- Placeholder filtering can hide a real secret that happens to contain one of those words.
- A clean scan is not proof that a repository is secret-free.

## Tests

```bash
python -m unittest -v
```

16 tests cover rule matching, masking, placeholder/allowlist behavior, entropy, directory walking, excludes, JSON, and exit codes.

## Files

```text
secret-scan-lite/
├── secret_scan_lite.py
├── test_secret_scan_lite.py
├── examples/clean.py
├── examples/leaky.py
├── README.md
├── .gitignore
└── .github/workflows/tests.yml
```
