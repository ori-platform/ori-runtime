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
- [ ] If capability-impacting files changed but matrix update is intentionally not needed, add `[skip-cap-matrix]` in PR body with rationale
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
- [ ] Tier C triggers declare `safe_default_action`, and it is a non-actuating action
- [ ] Every action is declared at or above its minimum tier in `ori/reasoning/action_registry.py`
- [ ] Any new executable action has a matching registry entry (registration is refused without one)
- [ ] The skill is within the workload budgets — triggers, sensors, the trigger × sensor product, and default actions per trigger
- [ ] `hooks.py` is clean and minimal
- [ ] No `subprocess` calls in hooks

> **Packaged skills run with the runtime's own authority.** Their `hooks.py` is
> imported directly into the runtime interpreter, and only packaged skills may
> declare `action_tier: D`. There is no sandbox standing between a bundled hook
> and the process — the previous in-process one was removed in v2.4.0 because it
> could be escaped. Review bundled hooks as runtime code, not as skill content.

## Related issue

<!-- Closes #<issue-number> -->

## Testing notes

<!-- Anything unusual about how this was tested? Hardware-specific? -->
