# Local PR Review SOP (CODEOWNERS)

Do not review from GitHub "Files changed" alone. Pull the PR branch locally and
run the quality gate before approving.

## 1) Fetch the PR locally

```bash
PR=36  # replace with target PR number

git switch main
git pull --ff-only origin main
git fetch origin pull/$PR/head:review/pr-$PR
git switch review/pr-$PR
```

If the contributor pushes updates to the same PR:

```bash
git fetch origin pull/$PR/head
git reset --hard FETCH_HEAD
```

## 2) Inspect scope versus main

```bash
git log --oneline --decorate origin/main..HEAD
git diff --name-status origin/main...HEAD
git diff --stat origin/main...HEAD
```

## 3) Run required checks locally

```bash
pre-commit run --all-files
pytest tests/ -v -m "not hardware"
```

Also run targeted tests for touched modules when relevant:

```bash
pytest -q tests/test_config.py tests/test_alert_failover.py
```

## 4) Review against runtime invariants

- Tier C approval path must remain reliable.
- Tier D must remain deterministic and independent of optional channels.
- Async paths must not introduce blocking I/O.
- Action executors must never raise (return `False` on failure).
- Config, docs, and tests must match runtime behavior.

## 5) Signed commit gate (required)

```bash
git log --show-signature --oneline origin/main..HEAD
```

All commits in the PR range must be verified-signed to pass protected branch
rules.

## 6) Clean up review branch

```bash
git switch main
git branch -D review/pr-$PR
```
