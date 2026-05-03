## What does this PR do?

<!-- Describe the change. Focus on WHY, not just what. -->

## Type of change

- [ ] `feat` — new feature
- [ ] `fix` — bug fix
- [ ] `docs` — documentation only
- [ ] `test` — tests only
- [ ] `refactor` — neither fixes a bug nor adds a feature
- [ ] `skill` — new or updated bundled skill
- [ ] `security` — touches a safety invariant (requires maintainer review even for skills)

## Checklist

### Required for all PRs

- [ ] `pytest tests/ -v` passes with 0 failures
- [ ] `ruff check --fix ori/ tests/ skills/` is clean
- [ ] Every new `.py` file has the Apache-2.0 license header
- [ ] If capability behavior changed, `docs/CAPABILITY_MATRIX.md` is updated in this PR
- [ ] PR description explains **why**, not just what

### If you used AI assistance

- [ ] I can explain every line of AI-generated code in this PR
- [ ] I have read and understood all files I am modifying
- [ ] I am not submitting code I cannot defend in a review conversation

### If this touches `/ori/` (core runtime)

- [ ] I opened an issue and discussed this change before writing code
- [ ] Every new Tier D code path has test coverage
- [ ] No new dependencies added without prior issue discussion

### If this adds or modifies a bundled skill (`/skills/`)

> **Community skills go to [ori-platform/ori-skills](https://github.com/ori-platform/ori-skills) — not here.**
> PRs to `/skills/` in this repo are for first-party bundled skills only.

- [ ] I opened an issue and got maintainer approval before writing this skill
- [ ] `action_tier` is declared on every trigger
- [ ] `bypass_llm: true` is only paired with `action_tier: D`
- [ ] Tier C triggers declare `safe_default_action`
- [ ] `hooks.py` is clean and minimal (bundled skills bypass the sandbox — they are implicitly trusted)
- [ ] No `subprocess` calls in hooks

## Related issue

<!-- Closes #<issue-number> -->

## Testing notes

<!-- Anything unusual about how this was tested? Hardware-specific? -->
