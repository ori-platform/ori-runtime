# Copyright 2026 Ori Nexus Systems LTD
# SPDX-License-Identifier: Apache-2.0

"""``SkillLoader``: discovery, selection and loading, over its other concerns.

The EventBus handler registered for each trigger returns in microseconds. With
a dispatch coordinator configured it hands the event to the event-wide barrier,
where the first handler to arrive evaluates every registered skill once and the
rest return; reasoning is scheduled there, and cooldown is charged there
against the outcome each trigger actually reached. Without one, the handler
checks cooldown itself and fires
``asyncio.create_task(elevator.reason_and_dispatch(...))``. Either way all I/O
— LLM inference, network, GPIO — runs inside a background task.
"""

import errno
import logging
import os
import stat
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

import yaml

from ori.config import MAX_SKILL_NAME_LENGTH, SKILL_NAME_RE
from ori.skills._manifest import (
    BUNDLED_SIGNATURE_SENTINEL,
    MAX_DIRECTORY_ENTRIES,
    MAX_MANIFEST_BYTES,
    MAX_SKILLS_PER_LOAD,
    MAX_TOTAL_SUBSCRIPTIONS,
    SelectedSkill,
    Skill,
    SkillSelectionError,
    SkillValidationError,
    UniqueStringKeySafeLoader,
)
from ori.skills._provenance import (
    first_party_skill_roots,
    is_skill_directory,
)
from ori.skills._registration import (
    SkillRegistration,
    refuse_asynchronous_hooks,
)
from ori.skills._validation import (
    SkillValidation,
    refuse_unresolved_names_in_tier_d_condition,
)
from ori.skills.sandbox import SkillAnchorError, SkillSecurityError
from ori.skills.signing import verify_community_skill_signature
from ori.utils.path_utils import shown

# Every part of the loader logs as it did before the split, under one name an
# operator's logging configuration may already select.
logger = logging.getLogger("ori.skills.loader")


class SkillLoader(SkillValidation, SkillRegistration):
    """Loads, validates, and registers skills from the filesystem.

    Args:
        elevator: :class:`~ori.reasoning.elevator.IntelligenceElevator` instance.
        state_store: :class:`~ori.state.store.StateStore` instance (may be ``None``
            during testing).
        dispatcher: :class:`~ori.reasoning.action_dispatcher.ActionDispatcher`
            instance (may be ``None`` during testing).
    """

    def load_all(self, skills_dir: str) -> list[Skill]:
        """Load every skill sub-directory found under *skills_dir*.

        Each immediate child directory that contains a ``skill.yaml`` is treated
        as a skill.  Directories without ``skill.yaml`` are silently skipped.
        Skills that fail validation are logged and skipped — a single bad skill
        must not prevent the others from loading.

        Args:
            skills_dir: Path to the directory containing skill sub-directories.

        Returns:
            List of successfully loaded :class:`Skill` objects.
        """
        anchor_fault = self.community_anchor_fault()
        self._admission = self._admission_report(fault=anchor_fault)

        root = Path(skills_dir)
        if not root.is_dir():
            logger.warning(
                "SkillLoader: skills_dir %s does not exist", shown(skills_dir)
            )
            return []

        loaded = self._load_candidates(self._discover_candidates(root), anchor_fault)
        return [skill for _, skill in loaded]

    def load_selected(
        self, selection: Sequence[tuple[str, str]], skills_dir: str
    ) -> list[Skill]:
        """Load exactly the skills a deployment's ``skills:`` list names.

        Each name resolves to ``<skills_dir>/<name>`` or to the packaged skill
        of that name, wherever the runtime is installed. A directory in
        *skills_dir* that no entry names is not loaded.

        Args:
            selection: ``(name, version)`` per entry; an empty version accepts
                whatever version the skill declares.
            skills_dir: The deployment's skills directory.

        Raises:
            SkillSelectionError: Naming every entry that is not a skill name,
                is named twice, resolves to no skill or to two, names a skill
                whose manifest declares a different name or version, or names
                a packaged skill that did not load. A community skill that
                resolves and then is not admitted is reported as
                :meth:`load_all` reports it and counted in
                :meth:`community_admission`; it cannot hold Tier D.
        """
        anchor_fault = self.community_anchor_fault()
        self._admission = self._admission_report(fault=anchor_fault)

        root = Path(skills_dir)
        # Resolution is the one place a selection's identity is decided: its
        # path and whether it ships with the runtime, from one snapshot of the
        # packaged roots. Everything after reads that record. Asked of the
        # filesystem again later, a directory swapped in between would turn a
        # packaged skill that failed into a community one that is merely not
        # admitted, and the start or reload would go ahead without it.
        entries = {
            entry.path: entry for entry in self._resolve_selection(selection, root)
        }
        faults: list[str] = []
        disagreeing: set[Path] = set()

        # Checked as each skill is read, before anything else can skip it: a
        # manifest that disagrees with its entry is refused whatever loaded
        # first, never shadowed by the duplicate-name rule.
        def against_entry(child: Path, skill: Skill) -> bool:
            entry = entries[child]
            if skill.first_party != entry.packaged:
                fault = f"{entry.name!r} changed provenance between resolution and load"
            elif skill.name != entry.name:
                fault = (
                    f"{entry.name!r} resolves to {shown(child)}, whose skill.yaml "
                    f"declares the name {skill.name!r}"
                )
            elif entry.version and skill.version != entry.version:
                fault = (
                    f"{entry.name!r} pins version {entry.version!r}, and the "
                    f"skill it resolves to is version {skill.version!r}"
                )
            else:
                return True
            faults.append(fault)
            disagreeing.add(child)
            return False

        # Packaged skills are read first, so community skills cannot spend the
        # subscription budget a packaged one needs.
        ordered = sorted(entries, key=lambda path: not entries[path].packaged)
        loaded = dict(self._load_candidates(ordered, anchor_fault, against_entry))
        self._note_unselected(root, set(entries))

        skills: list[Skill] = []
        for path, entry in entries.items():
            skill = loaded.get(path)
            if skill is not None:
                skills.append(skill)
            elif path not in disagreeing and entry.packaged:
                faults.append(
                    f"{entry.name!r} ships with the runtime and did not load; "
                    "the reason is logged above"
                )
        if faults:
            raise SkillSelectionError("; ".join(faults))
        return skills

    def _resolve_selection(
        self, selection: Sequence[tuple[str, str]], root: Path
    ) -> list[SelectedSkill]:
        if len(selection) > MAX_SKILLS_PER_LOAD:
            raise SkillSelectionError(
                f"skills: names {len(selection)} skills; the limit per load is "
                f"{MAX_SKILLS_PER_LOAD}"
            )
        roots = first_party_skill_roots()
        resolved: list[SelectedSkill] = []
        faults: list[str] = []
        folded: set[str] = set()
        for name, version in selection:
            # Config refuses these too; this layer does not rely on it. Names
            # are folded because a case-insensitive filesystem resolves two
            # spellings to one directory.
            if len(name) > MAX_SKILL_NAME_LENGTH or not SKILL_NAME_RE.fullmatch(name):
                faults.append(f"{name!r} is not a skill name")
                continue
            if name.casefold() in folded:
                faults.append(f"{name!r} is named a second time")
                continue
            folded.add(name.casefold())
            if name == "template":
                faults.append(f"{name!r} is a scaffold, not a skill")
                continue
            local = (root / name).resolve() if is_skill_directory(root / name) else None
            # The first packaged root holding the name, as bundled_skill_path
            # finds it: a checkout with the package also installed has two.
            packaged = next(
                (
                    (base / name).resolve()
                    for base in roots
                    if is_skill_directory(base / name)
                ),
                None,
            )
            if local is not None and self._is_core_bundled_skill(local):
                resolved.append(SelectedSkill(name, version, local, packaged=True))
            elif local is not None and packaged is not None:
                faults.append(
                    f"{name!r} is both a skill that ships with the runtime and "
                    f"a directory in {shown(root)}; rename or remove the directory"
                )
            elif local is not None:
                resolved.append(SelectedSkill(name, version, local, packaged=False))
            elif packaged is not None:
                resolved.append(SelectedSkill(name, version, packaged, packaged=True))
            else:
                faults.append(
                    f"{name!r} is neither a directory in {shown(root)} nor a "
                    "skill that ships with the runtime"
                )
        if faults:
            raise SkillSelectionError("; ".join(faults))
        return resolved

    def _note_unselected(self, root: Path, selected: set[Path]) -> None:
        """Name the skill directories in *skills_dir* that ``skills:`` leaves out.

        Every directory there used to load, so one that stops loading on
        upgrade is named rather than lost without a word. That includes a
        *skills_dir* that is the packaged directory, as in a source checkout.
        """
        if not selected:
            logger.warning("SkillLoader: skills: names no skill, so no skill is loaded")
        if not root.is_dir():
            return
        unselected = sorted(
            child.name
            for child in self._discover_candidates(root)
            if child.resolve() not in selected
        )
        if unselected:
            logger.warning(
                "SkillLoader: %s holds skills that skills: does not name, which "
                "are not loaded: %s",
                shown(root),
                ", ".join(shown(name) for name in unselected),
            )

    def _load_candidates(
        self,
        candidates: Sequence[Path],
        anchor_fault: str | None,
        admit: Callable[[Path, Skill], bool] | None = None,
    ) -> list[tuple[Path, Skill]]:
        skills: list[tuple[Path, Skill]] = []
        seen_names: dict[str, Path] = {}
        subscription_total = 0
        refused_by_anchor: list[Path] = []
        # Every community directory that did not become a loaded skill,
        # however it failed. A packaged skill that fails to load is a
        # packaging fault rather than a community-admission one, so it is not
        # counted here.
        community_not_admitted: set[Path] = set()

        def _note_not_admitted(child: Path) -> None:
            if not self._is_core_bundled_skill(child):
                community_not_admitted.add(child)

        for child in candidates:
            try:
                skill = self.load_one(child)
                if admit is not None and not admit(child, skill):
                    continue

                # Names identify skills in logs, action records and operator
                # messages. Two skills answering to one name makes those records
                # ambiguous exactly where they are used to attribute a physical
                # action, so the second is refused rather than silently shadowing
                # the first.
                previous = seen_names.get(skill.name)
                if previous is not None:
                    logger.error(
                        "SkillLoader: skipping %s — skill name %r is already "
                        "loaded from %s",
                        shown(child),
                        skill.name,
                        shown(previous),
                    )
                    _note_not_admitted(child)
                    continue

                # Per-skill caps are a per-file courtesy without this: sixty
                # individually legal skills add up to an illegal total, and the
                # event loop sees the sum, not the individual files.
                cost = self._subscription_cost(skill)
                if subscription_total + cost > MAX_TOTAL_SUBSCRIPTIONS:
                    logger.error(
                        "SkillLoader: skipping %s — its %d handlers would take "
                        "the load past the cumulative limit of %d "
                        "subscriptions (%d already committed)",
                        shown(child),
                        cost,
                        MAX_TOTAL_SUBSCRIPTIONS,
                        subscription_total,
                    )
                    _note_not_admitted(child)
                    continue
                subscription_total += cost

                seen_names[skill.name] = child
                skills.append((child, skill))
                logger.info(
                    "SkillLoader: loaded skill %r v%s from %s",
                    skill.name,
                    skill.version,
                    shown(child),
                )
            except SkillValidationError as exc:
                _note_not_admitted(child)
                logger.error(
                    "SkillLoader: validation failed for %s — %s",
                    shown(child.name),
                    exc,
                )
            except SkillAnchorError:
                # One deployment fault, reported once below. Logging it per
                # skill buries the misconfiguration under a count of the
                # skills it happened to affect.
                _note_not_admitted(child)
                refused_by_anchor.append(child)
            except SkillSecurityError as exc:
                _note_not_admitted(child)
                logger.error(
                    "SkillLoader: security validation failed for %s — %s",
                    shown(child.name),
                    exc,
                )
            except Exception:
                _note_not_admitted(child)
                logger.exception(
                    "SkillLoader: unexpected error loading skill from %s",
                    shown(child),
                )

        if refused_by_anchor:
            logger.error(
                "SkillLoader: %d community skill(s) were not loaded — %s. Affected: %s",
                len(refused_by_anchor),
                anchor_fault,
                ", ".join(sorted(shown(child.name) for child in refused_by_anchor)),
            )
        self._admission = self._admission_report(
            fault=anchor_fault, refused=len(community_not_admitted)
        )
        return skills

    def validate_one(self, skill_dir: Path | str) -> Skill:
        """Answer "would the runtime activate this?" **without executing it**.

        Inspecting a skill must not run it: listing and validation used to go
        through :meth:`load_one`, which imports ``hooks.py``, so displaying an
        untrusted skill's name executed its top-level code.

        Every check the runtime applies is applied here, including the hook
        activation policy — only the execution is skipped. A validation that
        approved skills the runtime then refused would be worse than none,
        because it would be consulted precisely when someone is deciding
        whether a skill is safe to install.

        Args:
            skill_dir: Path to the skill directory.

        Returns:
            A validated :class:`Skill` with no hooks attached.

        Raises:
            SkillSecurityError: If the runtime would refuse to activate it.
        """
        return self.load_one(skill_dir, load_hooks=False)

    def inspect_one(self, skill_dir: Path | str) -> Skill:
        """Parse and validate for **reporting**, without the activation policy.

        This is for listing: a skill the runtime will not activate still has a
        name and a version worth showing, and an operator looking at the list
        is usually trying to find out why. Use :meth:`validate_one` to decide
        whether a skill is usable; use this only to describe one.

        Nothing is executed here either.
        """
        return self.load_one(skill_dir, load_hooks=False, enforce_hook_policy=False)

    def load_one(
        self,
        skill_dir: Path | str,
        *,
        load_hooks: bool = True,
        enforce_hook_policy: bool = True,
    ) -> Skill:
        """Load and validate a single skill from *skill_dir*.

        Reads ``skill.yaml`` (required) and ``hooks.py`` (optional) from
        *skill_dir*.

        Args:
            load_hooks: When ``False``, ``hooks.py`` is neither read nor
                executed and ``Skill.hooks`` is ``None``. The activation policy
                still applies unless *enforce_hook_policy* is also ``False``.
            enforce_hook_policy: When ``False``, a skill whose hooks the runtime
                would refuse to activate is still returned. For reporting only.
                Prefer :meth:`validate_one` or :meth:`inspect_one` over passing
                these directly.
            skill_dir: Path to the skill directory (``str`` or :class:`~pathlib.Path`).

        Returns:
            A validated :class:`Skill` instance.

        Raises:
            SkillValidationError: If any trigger violates the Action Tier Framework.
            FileNotFoundError: If ``skill.yaml`` is missing.
            yaml.YAMLError: If the YAML is malformed.
        """
        skill_dir = Path(skill_dir)
        yaml_path = skill_dir / "skill.yaml"
        raw = (
            yaml.load(
                self._read_manifest_bytes(yaml_path),
                Loader=UniqueStringKeySafeLoader,
            )
            or {}
        )
        if not isinstance(raw, dict):
            raise SkillValidationError(
                f"Skill {skill_dir.name!r}: skill.yaml must be a mapping"
            )

        self._validate_skill_metadata(raw, skill_dir)
        self._validate_identity_fields(raw, skill_dir)
        self._validate_workload_budgets(raw, raw.get("name", "<unknown>"))

        first_party = self._is_core_bundled_skill(skill_dir)
        triggers = self._parse_triggers(
            raw.get("triggers") or [],
            raw.get("name", "<unknown>"),
            first_party=first_party,
        )
        actions = raw.get("actions") or {}
        self._validate_actions(
            actions,
            raw.get("name", "<unknown>"),
            trigger_names=[t.name for t in triggers],
        )
        self._validate_tier_b_trigger_policies(
            triggers,
            actions,
            raw.get("name", "<unknown>"),
        )
        prompts = raw.get("prompts") or {}
        self._validate_history_placeholder_count(
            prompts=prompts,
            skill_name=raw.get("name", "<unknown>"),
            trigger_names=[t.name for t in triggers],
        )
        self._validate_reserved_config_names(
            raw.get("config") or {},
            raw.get("name", "<unknown>"),
        )
        config = raw.get("config")
        for trigger in triggers:
            if trigger.action_tier == "D":
                refuse_unresolved_names_in_tier_d_condition(
                    raw.get("name", "<unknown>"),
                    trigger.name,
                    trigger.condition,
                    config if isinstance(config, dict) else {},
                )
        self._verify_community_signature(raw, skill_dir)
        if load_hooks:
            hooks = self._load_hooks(skill_dir)
            refuse_asynchronous_hooks(raw.get("name", "<unknown>"), hooks)
        else:
            if enforce_hook_policy:
                self._assert_hooks_activatable(skill_dir)
            hooks = None

        return Skill(
            name=raw.get("name", ""),
            version=raw["version"],
            author=raw.get("author", ""),
            sensors_required=raw.get("sensors_required") or [],
            triggers=triggers,
            prompts=prompts,
            actions=raw.get("actions") or {},
            config=raw.get("config") or {},
            hooks=hooks,
            first_party=first_party,
        )

    def _read_manifest_bytes(self, yaml_path: Path) -> str:
        """Read ``skill.yaml`` under admission limits, before parsing it.

        The path is opened **once**, and every decision is taken from that one
        descriptor. An earlier version called ``lstat()``, validated the result,
        then opened the path separately — which is check-then-use: the path can
        be replaced with a symlink, FIFO or device node between the two calls,
        so the file that was inspected need not be the file that was read. That
        defeats the exact property the check claimed to establish.

        The flags carry the guarantees instead:

        - ``O_NOFOLLOW`` fails if the final component is a symlink, so the
          symlink case is refused by the kernel rather than by a prior check.
        - ``O_NONBLOCK`` means opening a FIFO returns immediately instead of
          blocking until a writer appears — a named pipe in the skills
          directory fails startup rather than hanging it indefinitely.
        - ``O_CLOEXEC`` keeps the descriptor out of any child process.

        ``fstat()`` on the descriptor then decides the file type, and the bytes
        are read from that same descriptor under an explicit cap, so an
        oversized manifest cannot exhaust memory before the runtime has decided
        whether to trust it.

        Structural limits — alias rejection, nesting depth, node and collection
        budgets — are enforced during parsing by
        :class:`UniqueStringKeySafeLoader`, because a byte bound does not bound
        the structure a document expands into.
        """
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
        # Both are POSIX; guarded so a platform without them still builds
        # rather than failing at import.
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)

        try:
            fd = os.open(yaml_path, flags)
        except FileNotFoundError:
            raise
        except OSError as exc:
            # ELOOP is O_NOFOLLOW refusing a symlink. Anything else is reported
            # as an inspection failure rather than guessed at.
            if exc.errno == errno.ELOOP:
                raise SkillSecurityError(
                    f"Skill {yaml_path.parent.name!r}: skill.yaml is a symlink. "
                    "Manifests must be regular files so the bytes validated are "
                    "the bytes on disk."
                ) from exc
            raise SkillValidationError(
                f"Skill {yaml_path.parent.name!r}: skill.yaml could not be "
                f"opened ({exc.__class__.__name__})."
            ) from exc

        try:
            stat_result = os.fstat(fd)
            if not stat.S_ISREG(stat_result.st_mode):
                raise SkillSecurityError(
                    f"Skill {yaml_path.parent.name!r}: skill.yaml is not a "
                    "regular file. A FIFO or device node would block startup "
                    "rather than fail it."
                )
            if stat_result.st_size > MAX_MANIFEST_BYTES:
                raise SkillValidationError(
                    f"Skill {yaml_path.parent.name!r}: skill.yaml is "
                    f"{stat_result.st_size} bytes, above the "
                    f"{MAX_MANIFEST_BYTES} byte limit."
                )

            # One byte beyond the cap distinguishes "at the limit" from
            # "truncated", covering a file that grows after fstat.
            chunks: list[bytes] = []
            remaining = MAX_MANIFEST_BYTES + 1
            while remaining > 0:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            data = b"".join(chunks)
        finally:
            os.close(fd)

        if len(data) > MAX_MANIFEST_BYTES:
            raise SkillValidationError(
                f"Skill {yaml_path.parent.name!r}: skill.yaml exceeds the "
                f"{MAX_MANIFEST_BYTES} byte limit."
            )
        try:
            return data.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise SkillValidationError(
                f"Skill {yaml_path.parent.name!r}: skill.yaml is not valid UTF-8."
            ) from exc

    def _discover_candidates(self, root: Path) -> list[Path]:
        """Find at most ``MAX_SKILLS_PER_LOAD`` manifests to attempt.

        The cap counts **candidates**, not successes. Counting successes made
        the limit meaningless against the case it exists for: rejected
        manifests — unsigned, malformed, duplicate, over-budget — never
        incremented it, so an unlimited number of them could each be driven
        through file admission, parsing and validation before being thrown
        away. The work is spent whether or not the skill loads.

        Discovery streams with :func:`os.scandir` and stops early, rather than
        materialising the whole directory first. A directory with a million
        entries should not become a million ``Path`` objects before the limit
        is consulted.

        A separate ceiling bounds entries *examined*, so a directory padded
        with non-skill entries cannot force an unbounded walk looking for the
        64th candidate.

        Candidates are sorted before loading so the set that loads is stable
        for a given directory. Which candidates are found is filesystem order
        when the caps bite; that is the cost of not reading everything first,
        and the limits exist precisely for directories nobody curated.
        """
        candidates: list[Path] = []
        examined = 0
        truncated = False
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    examined += 1
                    if examined > MAX_DIRECTORY_ENTRIES:
                        truncated = True
                        logger.error(
                            "SkillLoader: stopping discovery in %s after %d "
                            "entries — the directory is larger than the runtime "
                            "will scan",
                            shown(root),
                            MAX_DIRECTORY_ENTRIES,
                        )
                        break
                    # Template scaffolds are documentation, not runtime skills.
                    if entry.name == "template":
                        continue
                    try:
                        if not entry.is_dir(follow_symlinks=False):
                            continue
                    except OSError:
                        continue
                    child = Path(entry.path)
                    if not (child / "skill.yaml").exists():
                        continue
                    candidates.append(child)
                    if len(candidates) >= MAX_SKILLS_PER_LOAD:
                        truncated = True
                        logger.error(
                            "SkillLoader: %d candidate manifests found in %s — "
                            "the limit per load is %d; the rest are not read",
                            len(candidates),
                            shown(root),
                            MAX_SKILLS_PER_LOAD,
                        )
                        break
        except OSError:
            logger.exception(
                "SkillLoader: could not scan skills directory %s", shown(root)
            )
            return []

        if truncated:
            logger.warning(
                "SkillLoader: skill discovery was truncated in %s — some "
                "manifests were not considered",
                shown(root),
            )
        return sorted(candidates)

    def _verify_community_signature(
        self,
        raw: dict[str, Any],
        skill_dir: Path,
    ) -> None:
        """Verify signatures for every skill that is not first-party.

        Provenance is established positively: a skill is trusted because it
        ships inside this package, not because its path failed to match a
        directory the runtime expected untrusted skills to live in. Anywhere
        else — an operator-managed skills directory beside ori.yaml, a
        temporary path, removable media — is community content and verifies.
        """
        if self._is_core_bundled_skill(skill_dir):
            return

        signature = str(raw.get("signature") or "").strip()
        if signature == BUNDLED_SIGNATURE_SENTINEL:
            raise SkillSecurityError(
                "skill uses the bundled signature sentinel but does not ship "
                "with the runtime. Re-sign it with an 'ed25519:' signature."
            )

        # Raised as the anchor's fault rather than this skill's: nothing in
        # the file being read caused it, and every other community skill on
        # the device is about to be refused for the same reason.
        anchor_fault = self.community_anchor_fault()
        if anchor_fault is not None:
            raise SkillAnchorError(anchor_fault)
        trust_anchor = self._resolve_community_trust_anchor()

        verify_community_skill_signature(
            raw_skill=raw,
            trust_anchor_public_key_b64=trust_anchor,
        )
