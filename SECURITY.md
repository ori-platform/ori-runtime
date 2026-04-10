# Security Policy

Ori Runtime controls physical systems. Security issues can have real-world consequences.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| `0.1.x` (alpha) | Yes |
| `<0.1.0` | No |

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

