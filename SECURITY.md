# Security Policy

Ori Runtime controls physical systems. Security issues can have real-world consequences.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `2.3.x` (stable) | Yes |
| `<2.3.0` | No |

Production support is expressed as tested platform tuples, not as one global
interpreter version. A primary Raspberry Pi target cannot honestly require a
non-stock interpreter while claiming a straightforward authenticated bootstrap,
and Debian Bookworm supplies Python 3.11.

| Platform | Architecture | Python | Status |
| --- | --- | --- | --- |
| Raspberry Pi OS Bookworm | `aarch64` | 3.11 (stock) | Production-supported |
| Ubuntu 24.04 | `x86_64` | 3.12 (stock) | Production-supported |
| Raspberry Pi OS Trixie | `aarch64` | 3.13 (stock) | Bundle published, hardware validation pending |
| Other published bundles | `x86_64`, `aarch64` | 3.11, 3.12, 3.13 | Community compatibility |

The state store additionally requires **SQLite 3.39 or newer**: its history
queries use a `HAVING` clause on an aggregate query with no `GROUP BY`, and
older libraries reject that form. The three stock distribution rows above ship
newer libraries already — Bookworm 3.40.1, Ubuntu 24.04 3.45.1, Trixie 3.46.1.

This is a property of the host, not of the release. `sqlite3` binds to the
library the distribution supplies rather than to anything the bundle pins, so
"other published bundles" makes no claim about it — a bundle carries no SQLite.
Clearing the interpreter requirement does not imply clearing this one: a Python
built by hand on an older distribution satisfies one and not the other. The
runtime therefore checks the library when opening the store and refuses there,
rather than failing later inside a query.

Trixie is listed separately rather than as production-supported, because the
two are different claims and only one of them is evidenced. A published bundle
means the target builds, signs, verifies and passes the suite. Production
support means an installation was carried out on the hardware and survived a
reboot, and that has not been done for Trixie. The distinction is the whole
point of expressing support as tested tuples, so it is not collapsed here for
the convenience of a shorter table.

Fedora is deferred compatibility work. Its current releases ship Python 3.13,
which is now a published target, so the interpreter is no longer the obstacle —
what remains is that no Fedora tuple has been evidenced, and validating one is
distribution work rather than interpreter work.

## Reporting a Vulnerability

Use GitHub's private vulnerability reporting for this repository:

1. Go to the repository `Security` tab.
2. Click `Report a vulnerability`.
3. Submit details privately.

If private reporting is unavailable, contact the repository owner directly via GitHub.

Do not open public issues for undisclosed vulnerabilities.

## What to Include

Please include:

- Affected component and file paths
- Reproduction steps (minimal PoC)
- Impact (confidentiality/integrity/availability/safety)
- Whether physical actuation can be triggered or bypassed
- Suggested remediation (if available)

## Response Targets

For valid reports:

- Initial acknowledgment: within 72 hours
- Triage and severity decision: within 7 days
- Patch target:
  - Critical/high: as soon as possible, usually within 14 days
  - Medium/low: scheduled in normal release cadence

## Disclosure Policy

- Coordinate disclosure until a fix is available.
- Public disclosure is expected only after fix release or explicit maintainer approval.
- Security advisories and release notes will describe impact and mitigation.

## Scope and Priorities

Highest-priority findings include:

- Tier C/Tier D enforcement bypasses
- Skill sandbox escape or unsafe hook execution
- Unsafe rule-expression execution or AST guard bypass
- Unauthorized action execution via webhook/approval paths
- Secrets exposure in repo, config handling, or logs
- Supply-chain integrity issues in dependency/update paths

## Safe Harbor

Good-faith security research is welcome. We will not pursue action for:

- Testing within this repository and your own infrastructure
- Non-destructive proof-of-concept demonstrations
- Responsible private disclosure under this policy

Do not access or modify data/systems that you do not own or have permission to test.

## Operational Safety Note

If you discover an issue that can cause immediate physical harm, mark the report as urgent and clearly state:

- Trigger conditions
- Potential hazard
- Suggested temporary mitigation
