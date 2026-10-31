#!/usr/bin/env python3
# ---------------------------------------------------------------------------
# Canonical home: ai-company. Do not hand-edit consumer copies; re-run
# bootstrap-client.ps1.
# Repatriated from: stockforge scripts/review_gate.py
# Source commit: e1905a3 (stockforge, "feat(review-gate): P2 — close
#   merge-mechanics + classifier bypasses (port from agentforge-pe)")
# Source sha256: 5ccd7efd3850ebbce036e79d19991c10a639c86aa3696661e4d4f42b18985d9d
# Repatriation date: 2026-07-04
# NOTE: this header changes the file's own sha256 relative to the source
# value above (expected — the header is new bytes). Going forward, THIS
# ai-company copy is canonical; drift is tested between ai-company and its
# consumer repos (stockforge, AI_agent_Workspace, ...), not against the
# pre-header stockforge sha256. See docs/CROSS_MODEL_REVIEW_HARNESS.md.
# ---------------------------------------------------------------------------
"""review_gate — run-scoped v1 review results, CAS finalization, and merge checking.

The active path creates one immutable identity per invocation, one immutable result per reviewer,
and one run-scoped final marker written only by an orchestrator/adjudicator through expected-prior
CAS and atomic replacement. Actor independence is invocation identity; provider/model diversity is a
separate policy. The v0 shared token/ledger/marker implementation below is a read-only migration
checker. Its writer is reachable only through an in-process test flag and never through the CLI.

Why CONTENT binding (P1.1): a clean `git merge --no-ff` runs `pre-merge-commit` with NO MERGE_HEAD
(verified empirically) — the merged tip's SHA is not available, only the STAGED diff. So the marker
binds to the **blob hashes of the reviewed production files**, not a commit SHA. The hook classifies
via the staged diff and requires every merged production file's blob to be in the marker. This is
strict for every default-branch landing context and is date-insensitive. A staged commit or merge is
exempt only in a lease-bound isolated feature worktree because the complete branch diff is reviewed
when it lands on the default branch; requiring a staged marker there creates an unsatisfiable base
binding after the two branches diverge.

Design (governance-compatible, FAIL-CLOSED):
  - Reviewers write independent results; only an orchestrator/adjudicator finalizes.
  - Gates ONLY the pre-merge step; the human `git merge --no-ff` is still the release gate.
  - Fail-closed: any undeterminable state (git error, no base, no default branch) ⇒ BLOCK.
  - Fail-closed classifier: every changed file is production UNLESS clearly exempt
    (under docs/ or tests/, a doc/data suffix, or a .git* name). Trivial escape: a [trivial-ok]
    subject PREFIX (deliberate; never a mid-subject/body mention).
  - v1 state lives below .devteam/runs/<run_id>/ and is gitignored.

Hooks (no remote ⇒ no push; boundary = git merge --no-ff):
  - clean default merge      -> hooks/pre-merge-commit -> `check --staged` (no MERGE_HEAD).
  - conflicted default merge -> hooks/pre-commit runs `check --pre-commit`.
  - lease-bound isolated feature commit/merge -> exempt from staged landing checks; the default
    merge remains gated.
  - feature-branch / ritual / skill Stage-3 -> `check` (default..HEAD); the strict primary check.

Subcommands: identity-issue, record, finalize, and check. Use --help on each command for its v1
contract. `check --migration-version v0` is the only supported legacy operation.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

if hasattr(sys.stdout, "reconfigure"):  # Windows 主控台 cp950 → 強制 UTF-8
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

POLICY_ROOT = Path(__file__).resolve().parent.parent
# Hooks run this trusted policy bundle against a separate candidate worktree. Direct CLI use keeps
# both roots identical; the hook alone sets AI_COMPANY_GATE_TARGET_ROOT after verifying the bundle.
ROOT = Path(os.environ.get("AI_COMPANY_GATE_TARGET_ROOT", POLICY_ROOT)).resolve()


def _safe_which(cmd: str, excluded_roots: tuple[Path, ...] = ()) -> str | None:
    old_curdir_env = os.environ.get("NoDefaultCurrentDirectoryInExePath")
    os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
    try:
        discovered = shutil.which(cmd)
    finally:
        if old_curdir_env is None:
            os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
        else:
            os.environ["NoDefaultCurrentDirectoryInExePath"] = old_curdir_env

    try:
        cwd = Path.cwd().resolve()
    except Exception:
        cwd = None
    excluded = [exc.resolve() for exc in excluded_roots if exc is not None]
    if cwd is not None:
        excluded.append(cwd)

    if discovered:
        candidate = Path(discovered).resolve()
        if not any(candidate == exc or candidate.parent == exc or candidate.is_relative_to(exc) for exc in excluded):
            return str(candidate)

    path_entries = []
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        if not entry:
            continue
        try:
            p = Path(entry).resolve()
            if not any(p == exc or p.is_relative_to(exc) for exc in excluded):
                path_entries.append(entry)
        except Exception:
            continue
    filtered_path = os.pathsep.join(path_entries)
    if filtered_path:
        old_curdir_env = os.environ.get("NoDefaultCurrentDirectoryInExePath")
        os.environ["NoDefaultCurrentDirectoryInExePath"] = "1"
        try:
            discovered = shutil.which(cmd, path=filtered_path)
        finally:
            if old_curdir_env is None:
                os.environ.pop("NoDefaultCurrentDirectoryInExePath", None)
            else:
                os.environ["NoDefaultCurrentDirectoryInExePath"] = old_curdir_env
        if discovered:
            candidate = Path(discovered).resolve()
            if not any(candidate == exc or candidate.parent == exc or candidate.is_relative_to(exc) for exc in excluded):
                return str(candidate)
    return None


def _trusted_git_executable() -> str:
    """Resolve Git dynamically or via AI_COMPANY_GIT_BIN override, failing closed if unavailable."""
    override = os.environ.get("AI_COMPANY_GIT_BIN")
    if override:
        candidate = Path(override).expanduser().resolve()
        if candidate.is_file():
            return str(candidate)
        raise RuntimeError(f"trusted system Git executable is unavailable at AI_COMPANY_GIT_BIN={override!r}")
    discovered = _safe_which("git", excluded_roots=(ROOT,))
    if discovered:
        return str(Path(discovered).resolve())
    raise RuntimeError("trusted system Git executable is unavailable")


_TRUSTED_GIT = _trusted_git_executable()


def _load_first_party_module(name: str, relative_path: str, *, package: bool = False):
    """Load a gate dependency by its canonical file path, never by ambient import precedence."""
    path = (POLICY_ROOT / relative_path).resolve()
    if not path.is_file() or not path.is_relative_to(POLICY_ROOT):
        raise ImportError(f"first-party runtime module is unavailable: {relative_path}")
    existing = sys.modules.get(name)
    if existing is not None:
        existing_path = Path(str(getattr(existing, "__file__", ""))).resolve()
        if existing_path != path:
            raise ImportError(f"first-party runtime already resolved outside canonical path: {existing_path}")
        return existing
    locations = [str(path.parent)] if package else None
    spec = importlib.util.spec_from_file_location(name, path, submodule_search_locations=locations)
    if spec is None or spec.loader is None:
        raise ImportError(f"cannot load first-party runtime module: {relative_path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    loaded_path = Path(str(getattr(module, "__file__", ""))).resolve()
    if not loaded_path.is_relative_to(POLICY_ROOT):
        raise ImportError(f"first-party runtime resolved outside repository: {loaded_path}")
    return module

try:
    _load_first_party_module("runtime", "runtime/__init__.py", package=True)
    _load_first_party_module("runtime.orchestrator", "runtime/orchestrator/__init__.py", package=True)
    _load_first_party_module("runtime.role_runner", "runtime/role_runner/__init__.py", package=True)
    _load_first_party_module("runtime.role_runner.schema", "runtime/role_runner/schema.py")
    _workspace_module = _load_first_party_module("runtime.orchestrator.workspace", "runtime/orchestrator/workspace.py")
    _review_state_module = _load_first_party_module("runtime.orchestrator.review_state", "runtime/orchestrator/review_state.py")
    _workspace_cli_module = _load_first_party_module("runtime.orchestrator.workspace_cli", "runtime/orchestrator/workspace_cli.py")
    ReviewStateError = _review_state_module.ReviewStateError
    ReviewStateStore = _review_state_module.ReviewStateStore
    SourceBinding = _review_state_module.SourceBinding
    _lease_path = _workspace_module._lease_path
    _repository_id = _workspace_module._repository_id
    resolve_common_dir = _workspace_module.resolve_common_dir
    verify_active_feature_lease = _workspace_cli_module.verify_active_feature_lease
    _V1_IMPORT_ERROR: Exception | None = None
except Exception as exc:  # Legacy v0 read-only adapters may be deployed without the v1 runtime.
    ReviewStateError = RuntimeError  # type: ignore[assignment,misc]
    ReviewStateStore = None  # type: ignore[assignment,misc]
    SourceBinding = None  # type: ignore[assignment,misc]
    _repository_id = None  # type: ignore[assignment]
    _lease_path = None  # type: ignore[assignment]
    resolve_common_dir = None  # type: ignore[assignment]
    verify_active_feature_lease = None  # type: ignore[assignment]
    _V1_IMPORT_ERROR = exc

MARKER = ROOT / ".devteam" / "review_verdict.json"
RUNS_ROOT = ROOT / ".devteam" / "runs"
CONTRACT_DIRECTORY = POLICY_ROOT / "state" / "contracts"
DEFAULT_MIGRATION_VERSION = "v1"
ALLOW_LEGACY_WRITES_FOR_TESTS = False
# 身分綁定(Residual-1):orchestrator 在每次 spawn 前寫 run_token,並在每個 rd-implement
# spawn 後 append author_ledger。兩者皆 .devteam/ 下、gitignored(本機 token,不入歷史)。
RUN_TOKEN = ROOT / ".devteam" / "run_token.json"
AUTHOR_LEDGER = ROOT / ".devteam" / "author_ledger.jsonl"
_OK_VERDICTS = ("CLEAN", "ACCEPT")
_ALL_VERDICTS = ("CLEAN", "ACCEPT", "DEFECTS_FOUND", "REJECT")
_DELETED = "DELETED"  # sentinel "blob" for a deleted production file
# 合法審查角色(D2 白名單):非此二者(如 rd-implement 自蓋章)一律 BLOCK。
_REVIEW_ROLES = ("reviewer", "qe-verify", "security")
# Security-surface review is a panel, not a provider-specific exception. Every member must match
# one exact, reviewed provider/model pair below and carry a trusted, signed session attestation.
# However many reviewers are required, their invocation IDs and attested sessions must all be
# DISTINCT -- that is unchanged, and it holds even when they use the same eligible model.
#
# HOW MANY are required is no longer a constant (Keith's direction, 2026-09-06). Two were always
# demanded, on a rationale that never materialised: the second seat existed for PROVIDER diversity,
# and every panel this repository has ever run used the same provider and model in both seats.
# Charging every security-surface change double for a benefit never delivered is what this narrows.
#
# What the second seat DID deliver, measured across ORD-0034's five two-leg runs: INSTANCE
# diversity. In all five, at least one leg found something the other missed entirely, and the two
# most serious findings -- the lease-exemption fail-OPEN, and a working bypass caught in the final
# verification -- each came from ONE leg while the other returned CLEAN. So the second seat is kept
# exactly where losing a finding is unrecoverable: changes to the control itself and its trust root.
_SECURITY_REVIEWER_FLOOR = 1
_SECURITY_REVIEWER_DUAL = 2
# Forbidden-zone members no existing constant enumerates. Explicit, and labelled as explicit:
# install_hooks.py BINDS the pinned digest; verify-hook-integrity.ps1 DETECTS out-of-band tampering
# with the same hooks, and a detector must not need less review than the guard it watches; the last
# two are BUCKBOOST_BLUEPRINT:108's "metric definitions" -- the evidence ledger's writer and its
# validator.
_DUAL_REVIEW_EXTRA = frozenset({
    # The gate's own trust root.
    "scripts/install_hooks.py",        # BINDS the pinned digest
    "scripts/verify-hook-integrity.ps1",  # DETECTS out-of-band tampering with the same hooks
    "scripts/journal_append.py",       # BUCKBOOST_BLUEPRINT:108 "metric definitions" -- the
    "scripts/validate_journal_row.py",  # evidence ledger's writer and its validator
    # The SECOND fail-closed control family, which an earlier version of this function missed
    # entirely: the PreToolUse guard WIRING. `skills/front-desk/SKILL.md:122-126` enumerates these
    # by name as 進化禁區. sync.ps1 publishes claude-settings-enforcement.json into the live
    # settings file, bootstrap-client.ps1 stands that up on a new machine, lint-agents.ps1 is the
    # sole mechanical enforcer sync.ps1 runs fail-closed before copying anything, and
    # confidential-paths.json is what the confidential-path guard reads. Nothing detects a change
    # here after the fact: verify-hook-integrity.ps1 never inspects the live settings file.
    "config/claude-settings-enforcement.json",
    "config/confidential-paths.json",
    "sync.ps1",
    "bootstrap-client.ps1",
    "scripts/lint-agents.ps1",
    # front-desk:126's "any metric / gate definition" clause, on its own manifest text: it pins
    # review_gate's OK-verdict set and the review-role eligibility set to their live source.
    "config/frozen_constants.json",
    "scripts/front-desk-triage.ps1",       # the OTHER consumer of enforcement_surfaces.json --
                                           # the classifier that refuses forbidden-zone requests
    "scripts/requirements_gate.py",        # gate definition
    "config/review_gate_distribution.json",  # gate definition
    # The THIRD fail-closed control family, found by the third cold review. external_review.py is
    # by its own line 99 "this repo's only outbound-to-a-third-party-LLM seam". It holds
    # _egress_blocked() (the enforcement-surface + confidential-paths refusal), and
    # _egress_security_facts(), which is the ONLY source of the security_surface / secrets_present
    # facts that dual-reviewed policy/egress.py decides on. Making the config dual and leaving the
    # code that reads it single defeats the point: one commit can feed the honest module false
    # facts, or flip external=True to False and kill every guard downstream of it. On master this
    # file was dual (it is an `exact` entry AND the constant was a flat 2), so narrowing it was a
    # REGRESSION this change introduced rather than a hole it inherited.
    "scripts/external_review.py",
    # The FOURTH family: what reviewing is ALLOWED TO CONCLUDE. skills/dev-team/SKILL.md's binding
    # disposition rule resolves every finding to FIX, RESIDUAL or ESCALATE and says there is no
    # fourth option; RESIDUAL means "real, but dominated by an accepted residual -- file it, do not
    # fix it", and the dominance baseline is the easiest entry in this file. So one appended entry
    # decides what the NEXT review may conclude about a real defect. It is also fed to the outbound
    # seam as a suppression list (external_review.py --residuals-file). The audit this function
    # already cites names it at :104-107 as the paradigm argued high-harm member -- "editing it can
    # silently accept a real security defect" -- and the file's own header records that a false
    # entry has ALREADY suppressed real findings twice, once misdirecting two independent
    # reviewers. It was an `exact` entry and therefore dual on master; narrowing it was a
    # regression, and it is the one file in that set with a recorded history of the exact failure.
    "docs/ACCEPTED_REVIEW_RESIDUALS.md",
})
def _norm_surface(path: str) -> str:
    """The one spelling every membership test in this module compares against."""
    return path.replace("\\", "/").lower().lstrip("./")


# Normalised ONCE at import, because the comparison lowercases the candidate path and an entry
# written with a capital letter would therefore never match -- silently, with no error, leaving the
# file it was added to protect on ONE reviewer. That is exactly what happened when
# "docs/ACCEPTED_REVIEW_RESIDUALS.md" was first added above: every other member happens to be
# lowercase already, so nothing had ever exercised the mismatch, and the entry read as protection
# while providing none. Never compare against _DUAL_REVIEW_EXTRA directly; compare against this.
_DUAL_REVIEW_EXTRA_NORM = frozenset(_norm_surface(f) for f in _DUAL_REVIEW_EXTRA)

# Prefixes whose every member is maximum-harm by construction.
# `docs/ENFORCEMENT_SURFACE_AUDIT_2026-08-24.md:44-51` rates BOTH families that way in the same
# breath, and an earlier version of this function kept the first and dropped the second.
_DUAL_REVIEW_PREFIXES = (
    "hooks/",    # what invokes the gate at all
    "policy/",   # egress.py implements ADR-0012 default-deny; routing.py decides which model may
                 # review a security surface. Deleting two lines at policy/egress.py:47-48 makes
                 # enforcement-surface content egress-authorized.
    "providers/",  # the transport that would carry it. The same audit's Group 3 rates port.py,
                 # live.py and bindings/*.json "real" -- an earlier version of this tuple read
                 # lines 44-51 of that document and stopped at Group 1. Nine files; the live
                 # bindings are specification_only TODAY, which is a fact that can change in one
                 # commit and is therefore not a reason to review them less.
)
# EMPTY, and it stays empty until a decision row says otherwise. An earlier version of this file
# put agents/discovery.md and agents/requirements-analyst.md here and cited D-20260822-003 as the
# approval. That citation reads a BUILD brief's own "candidate criterion, offered to be critiqued
# rather than accepted unexamined" as if it were the decision's content, and it ignores the two
# APPROVED rows that came after it. D-20260824-004 (approve-stop-both-branches) rules the
# exemption set EMPTY on the criterion's own merits and supersedes D-20260824-001/002, and the
# harm path it names is this change verbatim: "the exemption lowers the review tier for edits to
# the role file itself". Nothing since reverses it. Re-populating this set is a change to a
# standing approved ruling, not an implementation detail.
_SINGLE_REVIEW_ADVISORY_ROLES: frozenset[str] = frozenset()
_SECURITY_REVIEWER_MODELS = frozenset({
    # Keith's direction, 2026-09-06, under AGENTS.md "Proportionality and owner direction".
    # High-assurance roster: any of these may fill what was previously the opus-only seat.
    ("anthropic", "opus"),
    # Owner-directed substitutes, 2026-09-24 & 2026-10-16; record exact executed model.
    ("anthropic", "claude-opus-5-5"),
    ("anthropic", "opus-5.5"),
    ("google", "gemini-3.8-flash-high"),
    ("google", "gemini-4-argon"),
    ("google", "gemini-4-argon-high"),
    ("google", "gemini-4-argon-medium"),
    ("openai", "gpt-6"),
    ("openai", "gpt-5.6-sol"),
    ("openai", "gpt-6-sol"),
    ("openai", "gpt-6-astra"),
})
_SECURITY_ATTESTATION_SCHEMA_VERSION = "1.0.0"
_SECURITY_ATTESTATION_NAMESPACE = "ai-company-security-review"
_SECURITY_ATTESTATION_SIGNERS = "config/security_review_allowed_signers"
_TRUSTED_BUNDLE_FILES = (
    "config/enforcement_surfaces.json",
    "config/security_review_allowed_signers",
    "runtime/__init__.py",
    "runtime/orchestrator/__init__.py",
    "runtime/orchestrator/review_state.py",
    "runtime/orchestrator/workspace.py",
    "runtime/orchestrator/workspace_cli.py",
    "runtime/role_runner/__init__.py",
    "runtime/role_runner/schema.py",
    "scripts/trusted_gate_launcher.ps1",
    "scripts/review_gate.py",
    "state/contracts/invocation-identity.schema.json",
    "state/contracts/review-final-marker.schema.json",
    "state/contracts/review-final-marker-v2.schema.json",
    "state/contracts/review-result.schema.json",
    "state/contracts/security-review-attestation.schema.json",
)
# Security surfaces (evolution zone): any match requires the approved security-review panel.
# FAIL-CLOSED:paths 不可解析(None)亦視為安全面。前綴目錄(hooks/、agents/…)以 / 結尾比對。
# SINGLE SOURCE OF TRUTH (special-track): the list is loaded from config/enforcement_surfaces.json,
# no longer inlined here. scripts/front-desk-triage.ps1 reads the SAME file, so the two consumers
# always derive an identical set.
CONFIG_ENFORCEMENT = POLICY_ROOT / "config" / "enforcement_surfaces.json"


def _load_enforcement_surfaces() -> tuple[tuple[str, ...], bool]:
    """Load the canonical enforcement-surface set from config/enforcement_surfaces.json; return
    (paths, ok):
      paths: normalized (lowercased, '/'-separated, prefixes keep a trailing '/') exact+prefixes.
      ok:    True only when the file was read + parsed + non-empty + well-shaped.
    FAIL-CLOSED (critical): any failure (missing / unreadable / malformed JSON / empty / wrong shape
    / blank item) returns ((), False); the caller then treats EVERY path as a security surface (the
    SAFE direction). A loader failure must NEVER make the classification LESS restrictive."""
    try:
        raw = CONFIG_ENFORCEMENT.read_text(encoding="utf-8")
    except (OSError, ValueError):
        # OSError: missing / unreadable. ValueError (incl. UnicodeDecodeError): a non-UTF-8 /
        # undecodable config. Both fail-closed here -- scoped to the READ only, so a genuine
        # json.loads ValueError is still handled by its own guard below.
        return ((), False)
    try:
        data = json.loads(raw)
    except ValueError:
        return ((), False)
    if not isinstance(data, dict):
        return ((), False)
    exact = data.get("exact")
    prefixes = data.get("prefixes")
    if not isinstance(exact, list) or not isinstance(prefixes, list):
        return ((), False)
    if not exact:                        # an empty 'exact' core is malformed/insufficient ->
        return ((), False)               # fail-closed (parity with the PowerShell loader)
    out: list[str] = []
    for e in exact:
        if not isinstance(e, str) or not e.strip():
            return ((), False)          # a non-string / blank item -> fail-closed
        out.append(e.replace("\\", "/").lower())
    for p in prefixes:
        if not isinstance(p, str) or not p.strip():
            return ((), False)
        q = p.replace("\\", "/").lower()
        out.append(q if q.endswith("/") else q + "/")
    if not out:                          # an empty set (both exact/prefixes empty) -> fail-closed
        return ((), False)
    return (tuple(out), True)


# Derive the security set at module load; _SECURITY_PATHS_OK=False means the canonical file is
# unusable -> fail-closed everywhere (every path is treated as a security surface).
_SECURITY_PATHS, _SECURITY_PATHS_OK = _load_enforcement_surfaces()


def _matches_enforcement(p: str) -> bool:
    """True iff a single NORMALIZED (lowercased, '/'-separated) path hits the canonical set.
    FAIL-CLOSED: canonical file unusable -> True. Exact equality, or a '/'-suffixed prefix matched
    via startswith (the bare prefix-directory name itself also matches)."""
    if not _SECURITY_PATHS_OK:
        return True
    q = p.lstrip("./")
    for s in _SECURITY_PATHS:
        if s.endswith("/"):
            if q == s.rstrip("/") or q.startswith(s):
                return True
        elif q == s:
            return True
    return False
# 豁免(只動這些 → trivial)。FAIL-CLOSED:其餘一律視為生產碼。
# tests/ 整體豁免(治理:test-only 無新生產邏輯=trivial);docs/ 僅豁免文件/資料,
# docs/ 下的可執行碼(.py/.sh/Dockerfile…)仍須審查。
_EXEMPT_SUFFIXES = (".md", ".txt", ".rst", ".jsonl", ".csv")
_EXEMPT_NAMES = (".gitignore", ".gitattributes", ".gitkeep")
# 任一路徑「分量」命中 → 視為可執行生產碼(防雙副檔名偽裝,如 loader.py.md / deploy.sh.csv),
# 任何位置(含 docs/)都擋。
_PROD_SUFFIXES = (
    ".py", ".sh", ".ps1", ".bat", ".cmd", ".ipynb", ".pl", ".rb", ".js", ".ts",
    ".toml", ".cfg", ".ini", ".yaml", ".yml", ".sql",
)
_PROD_NAMES = ("dockerfile", "makefile")  # 無副檔名的可執行/建置檔(basename)


def _read_env() -> dict[str, str]:
    """The environment every read below runs under: os.environ with GIT_DIR removed and NOTHING else.

    ``GIT_DIR`` silently overrides ``-C``, so without this every fact the gate reads -- the staged
    diff, HEAD, the default branch -- comes from whatever repository the caller named rather than
    from ROOT. Measured 2026-09-04 in scratch repositories (ORD-0034 / P0-26): with GIT_DIR pointing
    at an unrelated repository, ``git -C ROOT diff --cached`` returns the EMPTY STRING with EXIT 0,
    so ``_prod_entries`` cannot distinguish it from *nothing staged* and ``_cmd_check_v1`` exits 0
    with an unreviewed production change staged. It fails OPEN.

    ``GIT_INDEX_FILE`` is deliberately KEPT, exactly as in ``_linked_feature_stores``' probe_env:
    ORD-0031's B3 measured that dropping it sends index reads back to .git/index and lets a
    ``git commit --only`` edit through unseen. Measured again for this call site: with GIT_INDEX_FILE
    set and GIT_DIR popped the read is correct, so the two constraints do not collide.

    Nothing else is removed (ORD-0034 B14; GIT_INDEX_FILE's survival is B16). GIT_COMMON_DIR makes
    THIS read exit 128, which reaches callers as None and fails CLOSED, so scrubbing it would fix a
    false negative rather than a bypass -- that is P0-27. **That grading is scoped to this read and
    must not be carried further**: the same variable redirects trusted_gate_launcher.ps1's
    `config --local --get` anchors at exit 0, including the python executable it then RUNS. GIT_WORK_TREE does not affect this read at
    all -- that is P0-28.
    """
    env = dict(os.environ)
    env.pop("GIT_DIR", None)
    return env


def _git(*args: str, strip: bool = True) -> str | None:
    """跑 git;成功回 stdout(預設 strip);**失敗(非零/例外)回 None** 以利上層 fail-closed。
    strip=False 保留原始輸出(供 _commit_subject 保留前導空白判斷 [trivial-ok] 是否在第 0 欄)。

    Every call runs under _read_env(), which removes GIT_DIR and nothing else (ORD-0034 / P0-26).
    GIT_INDEX_FILE must keep being inherited -- see _read_env() and ORD-0031's B3."""
    try:
        r = subprocess.run([_TRUSTED_GIT, "-C", str(ROOT), *args],
                           capture_output=True, text=True, encoding="utf-8",
                           env=_read_env())
    except Exception:
        return None
    if r.returncode != 0:
        return None
    out = r.stdout or ""
    return out.strip() if strip else out


def _head() -> str:
    return _git("rev-parse", "HEAD") or ""


def _default_branch() -> str:
    """Resolve the repo's REAL default branch. AUTHORITATIVE source first: the exact symbolic ref
    `refs/remotes/origin/HEAD` (when configured by the repository's remote-management workflow).
    The local main/master heuristic checks
    exact `refs/heads/*` names as a LAST RESORT only: an agent can mint a spurious local `main` via
    `git branch main` (a
    hook-ALLOWED local ref write) and — if the heuristic outranked origin/HEAD — flip every
    downstream merge-base / diff-range onto the attacker-chosen base (the recorded CLI-gate
    defeat, BUCKBOOST_BLUEPRINT 2026-07-10 run-record open item 3). FAIL-CLOSED: neither
    resolvable -> "" (callers already BLOCK on an empty default).

    RESIDUAL (independent Opus cold review, 2026-07-12): this defeats the trivial `git branch
    main` primitive, but origin/HEAD itself is still hook-ALLOWED to repoint (`git symbolic-ref`
    is in $GitReadOnly, `git remote set-head`/`remote` is in $GitLocalWrite) -- a strict
    improvement over the prior main/master guess, not a full closure of "can an agent influence
    _default_branch()".

    R2.6 (fable-v1-design-pressure-test.md, D-20260713-020 K1, 2026-07-14): in the FALLBACK leg
    (origin/HEAD unresolvable), the prior heuristic returned the FIRST of ("main", "master") that
    exists locally -- i.e. it silently preferred "main" -- so an agent could mint a spurious local
    `main` (same hook-ALLOWED `git branch main` primitive as above) in a repo whose real default is
    `master`, with no origin configured yet (e.g. before scripts/install_hooks.py's `git remote
    set-head` step has run) to redirect every downstream merge-base/diff-range onto it. Fail-closed
    instead: if BOTH `main` and `master` exist locally and origin/HEAD did not resolve, the choice
    is AMBIGUOUS -> BLOCK (return "", same as "neither resolves" -- callers already treat an empty
    default as a hard failure). A repo with only one of the two names is unaffected (no ambiguity to
    exploit)."""
    head = _git("symbolic-ref", "--quiet", "refs/remotes/origin/HEAD")
    if head and head.startswith("refs/remotes/origin/"):
        b = head[len("refs/remotes/origin/"):]
        if b:
            return b
    present = [
        b
        for b in ("main", "master")
        if _git("rev-parse", "--verify", "-q", f"refs/heads/{b}") is not None
    ]
    if len(present) > 1:
        return ""
    if present:
        return present[0]
    return ""


def _lease_bound_feature_staged_context() -> bool:
    """Return True only for a positively identified isolated feature worktree.

    The staged exemption is security-sensitive: inequality against a locally mutable
    ``origin/HEAD`` is not proof that the current branch is a feature branch. Exemption therefore
    requires all of the following:

    - an active owner-bound Phase 0 lease loaded from the common Git directory;
    - a dedicated linked worktree whose physical path and exact branch match that lease;
    - exactly one local conventional integration ref (``main`` or ``master``), matching the lease;
    - the leased integration SHA is unchanged.

    Missing, corrupt, expired, ambiguous, or inconsistent state returns False. The caller then
    performs the normal staged production check and requires review evidence (fail closed).
    """

    if _V1_IMPORT_ERROR is not None or verify_active_feature_lease is None:
        return False
    pointer_path = ROOT / ".devteam" / "workspace_lease.json"
    try:
        verify_active_feature_lease(ROOT, pointer_path)
    except (OSError, ValueError, TypeError, KeyError):
        return False
    except Exception:
        # Workspace validation errors are deliberately folded into the same fail-closed outcome.
        return False
    return True


def _commit_subject(sha: str) -> str:
    """commit 主旨行(%s),**保留前導空白**。豁免標記只認主旨『第 0 欄』開頭,故前導空白 /
    body / 主旨中段提及 [trivial-ok] 皆不觸發(_git 預設會 strip,故此處取 strip=False 原始值)。"""
    out = _git("log", "-1", "--format=%s", sha, strip=False)
    return out.rstrip("\n") if out is not None else ""


def _is_production(path: str) -> bool:
    """FAIL-CLOSED:除非明確豁免,否則一律視為生產碼。case-insensitive(Windows)。
    順序:.git* 既定名 → tests/ 整體豁免(治理:test-only=trivial)→ 任一分量像可執行碼則為
    生產(雙副檔名偽裝在任何位置都擋,含 docs/)→ docs/ 其餘為文件/資料豁免 → 其餘看副檔名。
    故 .sh/.ps1/.bat/Dockerfile/Makefile/無副檔名執行檔/設定檔皆須審查;docs/x.py、docs/Dockerfile
    須審查而 docs/guide.md 免;裸名 docs/tests(非 docs//tests/ 前綴)視為生產。"""
    p = path.replace("\\", "/").lower()
    name = p.rsplit("/", 1)[-1]
    if name in _EXEMPT_NAMES:
        return False
    # Canonical enforcement surfaces override ordinary tests/docs/data exemptions. This must run
    # before the tests/ shortcut so the suites that define the gate cannot rewrite their own
    # protection without review.
    if _matches_enforcement(p):
        return True
    if p.startswith("tests/"):                        # 治理:測試碼=trivial,整體豁免
        return False
    looks_exec = name in _PROD_NAMES or any(
        "." + c in _PROD_SUFFIXES for c in name.split(".")[1:]
    )
    if looks_exec:                                    # 可執行碼(含雙副檔名偽裝)→ 生產,任何位置
        return True
    if p.startswith("docs/"):                         # docs 的文件/資料(非可執行)→ 豁免
        return False
    return not name.endswith(_EXEMPT_SUFFIXES)


def _is_root_run_state(path: str) -> bool:
    """Return True if path is a repo-root run-state or spec contract file (DEV_TEAM_RUN*.md or DEV_TEAM_SPEC*.md,
    case-insensitive). Non-root files (e.g. docs/DEV_TEAM_RUN.template.md, docs/archive/DEV_TEAM_RUN.md) are not run-states."""
    norm = path.strip().strip('"').strip("'").replace("\\", "/").strip().lower()
    if "/" in norm:
        return False
    is_run = (
        norm == "dev_team_run.md"
        or norm.startswith("dev_team_run_")
        or norm.startswith("dev_team_run-")
        or norm.startswith("dev_team_run.")
        or norm.startswith("dev_team_run ")
    )
    is_spec = (
        norm == "dev_team_spec.md"
        or norm.startswith("dev_team_spec_")
        or norm.startswith("dev_team_spec-")
        or norm.startswith("dev_team_spec.")
        or norm.startswith("dev_team_spec ")
    )
    return (is_run or is_spec) and norm.endswith(".md")


def _prod_entries(name_status: str | None, blob_of) -> list[str] | None:
    """把 `git diff --name-status` 輸出 → 生產檔內容指紋清單(排序、去重):每筆 "<blob>\\t<path>",
    刪除檔為 "DELETED\\t<path>"。任一無法取得 blob(git 錯誤)→ 回 None(fail-closed)。"""
    if name_status is None:
        return None
    out: list[str] = []
    for ln in name_status.splitlines():
        ln = ln.rstrip("\n")
        if not ln.strip():
            continue
        parts = ln.split("\t")
        if len(parts) < 2:
            continue
        status, path = parts[0], parts[-1]   # --no-renames ⇒ 每列 "<STATUS>\t<path>"
        if not _is_production(path):
            continue
        norm = path.replace("\\", "/")
        if status.startswith("D"):
            out.append(f"{_DELETED}\t{norm}")
            continue
        blob = blob_of(path)
        if blob is None:
            return None
        out.append(f"{blob}\t{norm}")
    return sorted(set(out))


def _staged_prod() -> list[str] | None:
    """合併/暫存情境:暫存區(merge 結果)相對 HEAD 的生產檔內容指紋。不需 MERGE_HEAD。"""
    ns = _git("diff", "--cached", "--no-renames", "--name-status", "HEAD")
    return _prod_entries(ns, lambda p: _git("rev-parse", f":{p}"))


def _branch_prod(base: str, tip: str) -> list[str] | None:
    """feature 分支情境:base..tip 的生產檔內容指紋(blob 取自 tip)。"""
    ns = _git("diff", "--no-renames", "--name-status", base, tip)
    return _prod_entries(ns, lambda p: _git("rev-parse", f"{tip}:{p}"))


def _paths(entries: list[str]) -> list[str]:
    return [e.split("\t", 1)[1] for e in entries if "\t" in e]


def _read_marker() -> dict | None:
    if not MARKER.exists():
        return None
    try:
        return json.loads(MARKER.read_text(encoding="utf-8"))
    except ValueError:
        return None


def _read_run_token() -> dict | None:
    """讀 orchestrator 寫的 run token = {role, model, spawn_id, issued_by:"orchestrator", ts}。
    FAIL-CLOSED:檔案不存在 / 非法 JSON / 缺任一必要欄(role/model/spawn_id 為非空字串,且
    issued_by == "orchestrator")→ 回 None。身分只認此 token,不認自述字串。"""
    if not RUN_TOKEN.exists():
        return None
    try:
        tok = json.loads(RUN_TOKEN.read_text(encoding="utf-8"))
    except ValueError:
        return None
    if not isinstance(tok, dict):
        return None
    if tok.get("issued_by") != "orchestrator":
        return None
    for k in ("role", "model", "spawn_id"):
        v = tok.get(k)
        if not isinstance(v, str) or not v.strip():
            return None
    return tok


def _last_author() -> dict | None:
    """讀 author_ledger.jsonl,回**最後一列**合法 rd-implement 紀錄 = {role:"rd-implement",
    model, spawn_id, ts};定義 last_author_model / last_author_spawn_id(rd-implement 是唯一
    生產碼作者,SKILL L62)。FAIL-CLOSED:檔不存在 / 空 / 最後一列非法或 model/spawn_id 空 → 回
    None(上層據此在 non-trivial 時 refuse)。"""
    if not AUTHOR_LEDGER.exists():
        return None
    try:
        lines = AUTHOR_LEDGER.read_text(encoding="utf-8").splitlines()
    except OSError:
        return None
    for ln in reversed(lines):
        if not ln.strip():
            continue
        try:
            row = json.loads(ln)
        except ValueError:
            return None                      # 最後一筆非法 JSON → fail-closed
        if not isinstance(row, dict):
            return None
        model, spawn = row.get("model"), row.get("spawn_id")
        if not isinstance(model, str) or not model.strip():
            return None
        if not isinstance(spawn, str) or not spawn.strip():
            return None
        return row
    return None                               # 全空白列 → 視同空 ledger


def _required_security_reviewers(paths) -> int:
    """How many independent attested reviewers this change needs: 2 for the control itself, else 1.

    The dual set is this repository's **evolution forbidden zone**, and the zone is named in three
    places that do not say the same thing -- so it is the UNION of them, not whichever one is
    quoted first. ``docs/plans/BUCKBOOST_BLUEPRINT.md:108`` names five categories.
    ``skills/front-desk/SKILL.md:122-126`` -- which ``D-20260822-003`` fact (b) calls *the canonical
    prose authority* for the zone -- enumerates seven files by name and then adds *any metric / gate
    definition*. ``docs/ENFORCEMENT_SURFACE_AUDIT_2026-08-24.md:44-51`` rates two whole prefixes
    maximum-harm in one breath. Everything else that is a security surface takes one cold review.

    One question, not a taxonomy: **does this change alter the trust root the gate runs from, the
    path by which it is invoked, what reviewing means, or how the evidence is measured?**

    **What the warrant for the single-reviewer tier is, and what it is NOT.** An earlier version
    said this "restores the triage BUCKBOOST_BLUEPRINT designed", putting ordinary security surfaces
    in that document's middle tier. That is backwards: the blueprint's middle tier is 一般
    (*ordinary*), and it assigns core/security/紅線 to the TOP tier by name. The honest warrant is
    backlog **P1-9**'s: ``config/enforcement_surfaces.json`` is *over-inclusive* relative to the
    forbidden zone -- ``components/`` alone contributes 17 files, 14% of the surface, for a pilot
    whose generator does not exist -- so a single constant was applying the top tier to a set much
    larger than the zone. Narrowing at the reviewer-count layer rather than fixing that config is a
    real decision with a real cost, not a restoration.

    THREE independent fail-closed control families exist here. Successive revisions of this function
    covered one, then two, then three -- each gap found by a different cold reviewer, and each one a
    file that supplies facts to a control the code had already made dual. **That is the defect
    class: a control reviewed twice whose input is reviewed once.** It is stated here because three
    rounds found three instances of it, and the fourth instance will not announce itself.

    (1) The review gate's own trust root -- the pinned bundle, ``hooks/``, what binds the
    digest and what detects tampering with it. (2) The **PreToolUse guard wiring** -- ``sync.ps1``
    publishes ``config/claude-settings-enforcement.json`` into the live settings file, which is what
    causes ``block-destructive-git.ps1`` and ``confidential-path-guard.ps1`` to run for every
    subagent at all, and ``config/confidential-paths.json`` is the redline denylist those guards and
    ``scripts/external_review.py`` read. One commit editing files that were ALL single under the
    earlier version could unwire both guards, and nothing detects it afterwards:
    ``verify-hook-integrity.ps1`` never inspects the live settings file. That family was missed
    because the boundary was drawn from the gate outward instead of from the documents inward. Two
    independent cold reviewers found it separately. (3) The **outbound egress seam** --
    ``scripts/external_review.py`` is the only place this repository sends anything to a third-party
    LLM, and it computes the very facts ``policy/egress.py`` refuses on, so leaving it single while
    the policy module is dual protects nothing. ``providers/`` is the transport underneath it.

    Derived where a source exists (``_TRUSTED_BUNDLE_FILES``, ``_REVIEW_ROLES``), because backlog
    P1-9 records enforcement-surface membership *asserted rather than derived* as a live problem
    here. **The rest is an explicit list and is labelled as one.** An earlier version called the
    whole thing derived, and QE measured that overstatement against a gap it had already produced:
    ``install_hooks.py`` was remembered as "what binds the digest" while
    ``verify-hook-integrity.ps1`` -- the detector for out-of-band tampering with the same hooks --
    was not. A guard reviewed twice whose tamper-detector is reviewed once is the P1-9 rot appearing
    inside the function that cites P1-9.

    **Every ``agents/*.md`` is dual. There is no advisory carve-out.** Two earlier versions had one:
    the first exempted eight roles, the second two, each citing ``D-20260822-003`` as approval. Both
    citations were wrong in the same way -- they read the BUILD brief's *"candidate criterion,
    offered to be critiqued rather than accepted unexamined"* as the decision's content, and neither
    mentioned that ``D-20260824-004`` later ruled the exemption set **EMPTY** and superseded
    ``D-20260824-001``/``002``. See ``_SINGLE_REVIEW_ADVISORY_ROLES``.

    FAIL-CLOSED, checked before anything else: an unusable enforcement-surface config, an unusable
    bundle list, an **empty** bundle or role set, ``None``, or an unparseable element all return the
    dual requirement. A mixed diff takes the strictest member.
    """
    if not _SECURITY_PATHS_OK:
        # The sibling degradation, checked FIRST. _is_security_surface treats an unusable
        # enforcement-surface config as "every path is a surface"; returning one reviewer in that
        # state would be strictly weaker than the constant this replaced, which demanded two.
        return _SECURITY_REVIEWER_DUAL
    try:
        bundle = {f.replace("\\", "/").lower() for f in _TRUSTED_BUNDLE_FILES}
        review_role_files = {f"agents/{role}.md" for role in _REVIEW_ROLES}
    except Exception:
        return _SECURITY_REVIEWER_DUAL
    if not bundle or not review_role_files:
        # An EMPTY source is not an exception, so the clause above never sees it. Measured before
        # this line existed: with the bundle emptied, review_gate.py itself asked for ONE reviewer.
        # Same class as the degraded-config path -- a source that stopped working must not be able
        # to quietly weaken the requirement.
        return _SECURITY_REVIEWER_DUAL
    if paths is None:
        return _SECURITY_REVIEWER_DUAL
    for p in paths:
        if not isinstance(p, str):
            return _SECURITY_REVIEWER_DUAL
        norm = p.replace("\\", "/").lower().lstrip("./")
        if norm in bundle or norm in _DUAL_REVIEW_EXTRA_NORM:
            return _SECURITY_REVIEWER_DUAL
        if norm.startswith(_DUAL_REVIEW_PREFIXES):
            return _SECURITY_REVIEWER_DUAL
        if norm in review_role_files:
            return _SECURITY_REVIEWER_DUAL
        if norm.startswith("agents/") and norm.endswith(".md"):
            if norm not in _SINGLE_REVIEW_ADVISORY_ROLES:
                return _SECURITY_REVIEWER_DUAL
        if norm.startswith("skills/") and norm.endswith("/skill.md"):
            return _SECURITY_REVIEWER_DUAL
    return _SECURITY_REVIEWER_FLOOR


def _dual_review_reason(paths) -> str:
    """Which member of the change actually forced two reviewers, for the BLOCK message.

    An earlier version hardcoded "the digest-pinned bundle, hooks/, or install_hooks.py" for every
    dual verdict. There are now ten categories that can force one, so an operator blocked by, say,
    an edit to `policy/egress.py` was told a reason that had nothing to do with their change --
    which reads like a broken gate rather than a working one.
    """
    try:
        for p in paths or ():
            if not isinstance(p, str):
                continue
            norm = p.replace("\\", "/").lower().lstrip("./")
            if norm in {f.replace("\\", "/").lower() for f in _TRUSTED_BUNDLE_FILES}:
                return f"{p} is part of the digest-pinned review-gate bundle"
            if norm in _DUAL_REVIEW_EXTRA_NORM:
                return f"{p} is in the evolution forbidden zone"
            if norm.startswith(_DUAL_REVIEW_PREFIXES):
                return f"{p} is under a maximum-harm prefix"
            if norm.startswith("agents/") and norm.endswith(".md"):
                return f"{p} defines an agent role"
            if norm.startswith("skills/") and norm.endswith("/skill.md"):
                return f"{p} is a SKILL iron-rule block"
    except Exception:
        pass
    return ("this change touches the evolution forbidden zone, or the enforcement-surface "
            "configuration could not be read and the gate failed closed")


def _is_security_surface(paths) -> bool:
    """FAIL-CLOSED: canonical file unusable (_SECURITY_PATHS_OK=False) / paths is None / any
    unparseable item -> True (treated as a security surface); otherwise any path hitting the
    canonical set _SECURITY_PATHS -> True. case-insensitive (Windows). Prefix-directory entries
    (trailing '/') match via startswith, the rest by exact equality. src/app.py and the like -> False."""
    if not _SECURITY_PATHS_OK:
        return True                           # canonical file unusable -> fail-closed everywhere
    if paths is None:
        return True
    for p in paths:
        if not isinstance(p, str):
            return True                       # 不可解析的項 → fail-closed
        if _matches_enforcement(p.replace("\\", "/").lower()):
            return True
    return False


def _resolve_summary(args, max_len: int) -> str:
    summary_arg = getattr(args, "summary", "") or ""
    summary_file = getattr(args, "summary_file", "") or ""
    if summary_arg and summary_file:
        raise ReviewStateError("cannot specify both --summary and --summary-file")
    if summary_file:
        path = Path(summary_file)
        try:
            summary = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise ReviewStateError(f"summary file cannot be loaded: {exc}") from exc
    else:
        summary = summary_arg

    if len(summary) > max_len:
        print(
            f"review-gate: WARNING -- summary exceeds {max_len} characters ({len(summary)} chars); truncated",
            file=sys.stderr,
        )
        summary = summary[:max_len]
    return summary


def _cmd_record_v0(args) -> int:
    sha = args.sha or _head()
    resolved = _git("rev-parse", "--verify", "-q", f"{sha}^{{commit}}") if sha else None
    if not resolved:
        print(f"✗ record: --sha {sha!r} 無法解析為 commit(此處是 git repo 嗎?)。")
        return 2
    db = _default_branch()
    base = _git("merge-base", db, resolved) if db else None
    prod = _branch_prod(base, resolved) if base else []
    if prod is None:
        print("✗ record: 無法計算審查範圍的生產檔(git 錯誤)。")
        return 2
    # 身分綁定(Residual-1)—— FAIL-CLOSED:token 與 ledger 皆在**任何 marker 寫入之前**驗證。
    # 驗不過即非零離開、不寫 marker、任何既有 marker 位元不動(--reviewer 僅當標籤,不作身分)。
    tok = _read_run_token()
    if tok is None:
        print("✗ record: 缺 / 非法 run token(.devteam/run_token.json,須由 orchestrator 簽發),"
              "身分不可驗證,拒絕寫 marker(fail-closed)。")
        return 2
    sec = _is_security_surface(_paths(prod))
    author = _last_author()
    if prod and author is None:
        # non-trivial(prod 非空,含 DELETED)但無合法 author ledger → refuse。空 prod(docs/tests)免。
        print("✗ record: non-trivial 變更(生產檔非空)但 author ledger 缺 / 空 / 非法"
              "(.devteam/author_ledger.jsonl),作者身分不可驗證,拒絕寫 marker(fail-closed)。")
        return 2
    try:
        summary = _resolve_summary(args, max_len=300)
    except ReviewStateError as exc:
        print(f"✗ record: {exc}")
        return 2
    rec = {
        "verdict": args.verdict,
        "reviewer": args.reviewer,           # 純標籤,check 永不讀取(身分認 token,見下)
        "reviewer_role": tok["role"],
        "reviewer_model": tok["model"],
        "reviewer_spawn_id": tok["spawn_id"],
        "author_model": author["model"] if author else "",
        "author_spawn_id": author["spawn_id"] if author else "",
        "security_surface": sec,
        "reviewed_sha": resolved,            # provenance only(綁定靠內容,非 SHA)
        "ts": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "summary": summary,
        "prod": prod,                        # 被審生產檔內容指紋(<blob>\t<path>)
    }
    MARKER.parent.mkdir(parents=True, exist_ok=True)
    MARKER.write_text(json.dumps(rec, ensure_ascii=False, indent=1), encoding="utf-8")
    print(f"✓ review marker 已寫:{args.verdict} @ {resolved[:8]}({len(prod)} 生產檔內容綁定;"
          f"reviewer={tok['role']}/{tok['model']},security_surface={sec})"
          f" → {MARKER.relative_to(ROOT)}")
    return 0


def _cmd_check_v0(args) -> int:
    # pre-commit 入口:把「何時該閘」收進共用碼。閘住所有「commit 落上預設分支」的路徑
    # (squash-merge / cherry-pick / git am / 直接 commit — 治理本就禁直接 commit)以及衝突合併
    # 完成(MERGE_HEAD)。一般 feature 分支 commit 不閘(於合併時審查)。狀態不明 → 仍閘(fail-closed)。
    if getattr(args, "pre_commit", False):
        merging = _git("rev-parse", "-q", "--verify", "MERGE_HEAD") is not None
        cur = _git("rev-parse", "--abbrev-ref", "HEAD")
        db = _default_branch()
        # 只有「明確在某個非 default 的具名分支」才算 feature commit(免閘)。detached HEAD 時
        # --abbrev-ref 回傳字面 "HEAD" → 視為狀態不明 → 仍閘(fail-closed,符合上面註解)。
        feature_commit = (not merging) and bool(db) and (cur is not None) and cur not in (db, "HEAD")
        if feature_commit:
            print("review-gate: feature 分支 commit,於合併時審查,免閘。")
            return 0
        args.staged = True   # 落上預設分支 / 衝突合併 / 狀態不明 → 走 staged 內容檢查(fail-closed)
    # 1) 取得本次變更的生產檔內容指紋(staged=合併/暫存;否則 feature 分支 default..HEAD)
    if args.staged:
        if _lease_bound_feature_staged_context():
            print("review-gate: lease-bound isolated feature staged commit/merge, no review required.")
            return 0
        staged_files = _git("ls-files", "--stage")
        if staged_files is None:
            print("✗ review-gate blocked: cannot inspect staged index files (fail-closed)")
            return 1
        for ln in staged_files.splitlines():
            if "\t" in ln:
                p = ln.split("\t", 1)[1].strip()
                if _is_root_run_state(p):
                    print(
                        f"✗ review-gate blocked: root run-state file '{p}' cannot land on default branch "
                        f"(DEV_TEAM_RUN*.md and DEV_TEAM_SPEC*.md must be deleted before merge; see skills/dev-team/SKILL.md)"
                    )
                    return 1
        prod = _staged_prod()
        why = "staged 合併內容"
    else:
        tip = args.target or _head()
        if not tip:
            print("✗ review-gate 擋下:無法解析 HEAD(fail-closed)。")
            return 1
        db = _default_branch()
        cur = _git("rev-parse", "--abbrev-ref", "HEAD")
        if db and (cur == db or _git("rev-parse", db) == tip):
            print("review-gate: 位於 default 分支、無待併變更,免審查。")
            return 0
        if not db:
            print("✗ review-gate 擋下:找不到 default 分支(main/master),無法判定範圍(fail-closed)。")
            return 1
        base = _git("merge-base", db, tip)
        if not base:
            print(f"✗ review-gate 擋下:無法判定相對 {db} 的 base(fail-closed)。")
            return 1
        if _commit_subject(tip).startswith("[trivial-ok]"):
            print("review-gate: [trivial-ok] 主旨前綴,免審查。")
            return 0
        prod = _branch_prod(base, tip)
        why = f"{db}..HEAD"
    if prod is None:
        print("✗ review-gate 擋下:無法計算變更內容(git 錯誤,fail-closed)。")
        return 1
    if not prod:
        print(f"review-gate: 只動到豁免檔(docs/tests/文件/資料),免審查({why})。")
        return 0
    # 2) 比對 marker:CLEAN 且每個被併生產檔的內容指紋都在已審集合內
    rec = _read_marker()
    if rec is None:
        print(f"✗ review-gate 擋下:non-trivial 變更({len(prod)} 生產檔,{why})缺獨立審查 marker。")
        print(f"  生產檔:{', '.join(_paths(prod)[:8])}{' …' if len(prod) > 8 else ''}")
        print("  請先跑獨立 fresh-context 審查(reviewer 代理)record marker;真要略過用 --no-verify(人工升級)。")
        return 1
    verdict = str(rec.get("verdict", "")).upper()
    if verdict not in _OK_VERDICTS:
        print(f"✗ review-gate 擋下:審查判定為 {verdict!r}(非 CLEAN/ACCEPT)。修正後重審。")
        return 1
    reviewed = set(rec.get("prod", []))
    missing = [e for e in prod if e not in reviewed]
    if missing:
        print("✗ review-gate 擋下:有未經審查的生產檔內容(marker 未涵蓋,或審後又改動):")
        print(f"  {', '.join(_paths(missing)[:8])}{' …' if len(missing) > 8 else ''}")
        print("  請對最新內容重審後 record。")
        return 1
    # 3) 身分綁定閘(Residual-1 D1-D5)——疊在既有 verdict + 內容涵蓋之上,任一未過 → exit 1、各有理由。
    #    身分只認 marker 內由 token/ledger 綁定的欄位;--reviewer 自述字串永不參與。
    rr = str(rec.get("reviewer_role", ""))
    rm = str(rec.get("reviewer_model", ""))
    rs = str(rec.get("reviewer_spawn_id", ""))
    am = str(rec.get("author_model", ""))
    a_s = str(rec.get("author_spawn_id", ""))
    # D1 身分齊全:五個身分欄皆非空(缺任一綁定欄 → 無 grandfathering,直接 BLOCK)。
    if not all(x.strip() for x in (rr, rm, rs, am, a_s)):
        print("✗ review-gate 擋下:marker 缺身分綁定欄(reviewer_role/model/spawn_id、"
              "author_model/spawn_id 須皆非空;舊 marker 不予寬待,fail-closed)。")
        return 1
    # D2 審查角色為合法審查角色(rd-implement 自蓋章 → BLOCK)。
    if rr not in _REVIEW_ROLES:
        print(f"✗ review-gate 擋下:reviewer_role={rr!r} 非審查角色"
              f"(須 ∈ {{{', '.join(_REVIEW_ROLES)}}};rd-implement 自蓋章不被接受)。")
        return 1
    # D4 安全面須 opus:先算 sec(fail-closed:paths 不可解析亦視為安全面)。
    sec = _is_security_surface(_paths(prod))
    # D3 作者 ≠ 審查者:預設以「模型層級」判別 —— reviewer_model == author_model → BLOCK
    #    (真正跨層 author=sonnet/reviewer=opus 通過)。例外:安全面上 D4 強制 reviewer=opus、
    #    SKILL L62 亦強制安全面 author=opus,兩者合法皆 opus → 改以 spawn 身分判別:
    #    spawn 不同才 PASS,同 spawn(安全面自蓋章)BLOCK。
    if rm == am:
        forced_opus = sec and rm == "opus"
        if forced_opus:
            if rs == a_s:
                print("✗ review-gate 擋下:安全面上同一 spawn 自蓋章"
                      "(reviewer_spawn_id == author_spawn_id;強制 Opus 面須跨 spawn 審查)。")
                return 1
            # rs != a_s 且 rr 已於 D2 確認為審查角色 → 合法,續下。
        else:
            print(f"✗ review-gate 擋下:author == reviewer(reviewer_model == author_model == "
                  f"{rm!r};非強制 Opus 安全面,須跨層/跨 spawn 由他人審查)。")
            return 1
    # D4 安全面須 opus:sec 為真時,reviewer_model 必須 opus(排除 fable / sonnet)。
    if sec and rm != "opus":
        print(f"✗ review-gate 擋下:安全面變更須 Opus 審查(security surface requires Opus reviewer;"
              f"reviewer_model={rm!r} 排除,fable/sonnet 不得審安全面)。")
        return 1
    # D5 spawn linkage(WARN-only,絕不誤擋):check 時若 run_token 在且 role 為審查角色,
    #    marker.reviewer_spawn_id 與 token.spawn_id 不符則 WARN,不 block(fail-closed 重量在 record)。
    tok = _read_run_token()
    if tok is not None and tok.get("role") in _REVIEW_ROLES and tok.get("spawn_id") != rs:
        print(f"⚠ review-gate 提醒:marker.reviewer_spawn_id({rs[:8]}…)與現場 run_token"
              f"({str(tok.get('spawn_id'))[:8]}…)不符 —— 僅提醒,不擋。")
    print(f"✓ review-gate 通過:{verdict}({len(prod)} 生產檔內容皆已審;"
          f"reviewer={rr}/{rm},author={am},security_surface={sec})。")
    return 0


def _v1_store() -> ReviewStateStore:
    if _V1_IMPORT_ERROR is not None or ReviewStateStore is None:
        raise ReviewStateError(f"v1 runtime is unavailable: {_V1_IMPORT_ERROR}")
    return ReviewStateStore(RUNS_ROOT, CONTRACT_DIRECTORY)


def _v1_source(target: str = "") -> tuple[SourceBinding, list[str]]:
    """Bind review evidence to a feature tip.

    A feature tip may retain DEV_TEAM_RUN.md and DEV_TEAM_SPEC.md while QE records its
    result and before the terminal journal append.  Those working artifacts remain forbidden
    only in the staged default-branch landing check, which runs after their required cleanup.
    """
    tip = target or _head()
    resolved = _git("rev-parse", "--verify", "-q", f"{tip}^{{commit}}") if tip else None
    default_branch = _default_branch()
    branch_ref = _git("symbolic-ref", "--quiet", "HEAD")
    branch_prefix = "refs/heads/"
    if (
        branch_ref
        and branch_ref.startswith(branch_prefix)
        and len(branch_ref) > len(branch_prefix)
    ):
        branch = branch_ref[len(branch_prefix):]
    else:
        branch = None
    base = _git("merge-base", default_branch, resolved) if default_branch and resolved else None
    prod = _branch_prod(base, resolved) if base and resolved else None
    if not resolved or not default_branch or not branch or not base or prod is None:
        raise ReviewStateError("Git source binding cannot be resolved")
    return (
        SourceBinding(
            repository_id=_repository_id(resolve_common_dir(ROOT)),
            branch=branch,
            base_sha=base,
            reviewed_tip_sha=resolved,
            policy_version="1.0.0",
        ),
        prod,
    )


def _load_findings(path: str) -> list[object]:
    if not path:
        return []
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewStateError(f"findings file cannot be loaded: {exc}") from exc
    if not isinstance(value, list):
        raise ReviewStateError("findings file must contain a JSON array")
    return value


def trusted_bundle_digest(policy_root: Path | None = None, normalise_newlines: bool = True) -> str:
    policy_root = policy_root or POLICY_ROOT
    digest = hashlib.sha256()
    for relative in _TRUSTED_BUNDLE_FILES:
        path = policy_root / relative
        if not path.is_file():
            raise ReviewStateError(f"trusted bundle file is missing: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        content = path.read_bytes()
        if normalise_newlines:
            content = content.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def cmd_trusted_bundle_check(args) -> int:
    try:
        observed = trusted_bundle_digest()
    except (OSError, ReviewStateError) as exc:
        print(f"✗ trusted-bundle-check blocked: {exc}")
        return 2
    if observed != args.expected_digest:
        print("✗ trusted-bundle-check blocked: trusted bundle digest mismatch")
        return 2
    print("✓ trusted review-gate bundle digest verified")
    return 0


def cmd_identity_issue(args) -> int:
    identity = {
        "schema_version": "1.0.0",
        "run_id": args.run_id,
        "invocation_id": args.invocation_id,
        "role": args.role,
        "provider": args.provider,
        "model": args.model,
        "runner_instance_id": args.runner_instance_id,
        "issued_by": "orchestrator",
        "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
    }
    try:
        path = _v1_store().issue_identity(identity)
    except ReviewStateError as exc:
        print(f"✗ identity-issue blocked: {exc}")
        return 2
    print(f"✓ immutable invocation identity created: {path}")
    return 0


def cmd_attestation_template(args) -> int:
    try:
        store = _v1_store()
        identity = store.read_identity(args.run_id, args.reviewer_invocation_id)
        result = store.read_result(args.run_id, args.reviewer_invocation_id)
        if identity["role"] not in _REVIEW_ROLES:
            raise ReviewStateError("security attestation requires a reviewer invocation")
        if not args.platform or len(args.platform) > 64:
            raise ReviewStateError("security attestation platform is invalid")
        if not args.session_id or len(args.session_id) > 256:
            raise ReviewStateError("security attestation session ID is invalid")
        if not args.attestor or len(args.attestor) > 128 or any(
            character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@-"
            for character in args.attestor
        ):
            raise ReviewStateError("security attestation attestor is invalid")
        payload_path, signature_path = _security_attestation_paths(
            store, args.run_id, args.reviewer_invocation_id
        )
        if signature_path.exists():
            raise ReviewStateError("security attestation signature already exists")
        payload = {
            "schema_version": _SECURITY_ATTESTATION_SCHEMA_VERSION,
            "platform": args.platform,
            "session_id": args.session_id,
            "attestor": args.attestor,
            "reviewer_invocation_id": args.reviewer_invocation_id,
            "provider": str(identity["provider"]),
            "model": str(identity["model"]),
            "reviewed_tip_sha": str(result["reviewed_tip_sha"]),
            "review_verdict": str(result["verdict"]),
            "review_result_sha256": hashlib.sha256(
                store.result_path(args.run_id, args.reviewer_invocation_id).read_bytes()
            ).hexdigest(),
            "issued_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        payload_text = json.dumps(
            payload, sort_keys=True, separators=(",", ":")
        ) + "\n"
        with payload_path.open("x", encoding="utf-8", newline="\n") as handle:
            handle.write(payload_text)
    except (OSError, ReviewStateError) as exc:
        print(f"✗ attestation-template blocked: {exc}")
        return 2
    print(
        "✓ security attestation template created; verify the platform session and sign this exact file: "
        f"{payload_path}"
    )
    return 0


def cmd_attestation_check(args) -> int:
    try:
        store = _v1_store()
        identity = store.read_identity(args.run_id, args.reviewer_invocation_id)
        result = store.read_result(args.run_id, args.reviewer_invocation_id)
        source = SourceBinding(
            repository_id=str(result["repository_id"]),
            branch=str(result["branch"]),
            base_sha=str(result["base_sha"]),
            reviewed_tip_sha=str(result["reviewed_tip_sha"]),
            policy_version=str(result["policy_version"]),
        )
        _, error = _security_reviewer_attestation_eligible(
            store, args.run_id, args.reviewer_invocation_id, identity, source
        )
        if error is not None:
            raise ReviewStateError(error)
    except (OSError, ReviewStateError) as exc:
        print(f"✗ attestation-check blocked: {exc}")
        return 2
    print("✓ security attestation is valid")
    return 0


def _warn_if_binding_is_empty(prod, what: str, sha: str) -> str | None:
    """A result or marker that binds NO production files can authorize nothing. Say so here.

    P1-15 (filed as P0-45 and downgraded once measured). ``--sha`` defaults to empty, so
    ``_v1_source`` uses ``_head()``; run that on the integration branch -- exactly where a merge is
    staged -- and base equals tip, so the production set is empty. Every stage then reports success:
    record, attestation-check, the OWNER'S SIGNATURE, and finalize. Only ``check --staged`` refuses,
    and only with a generic ``production content mismatch``.

    It is not a bypass -- an empty binding matches only an empty staged diff, for which the gate
    already answers "no v1 review required" -- so this WARNS rather than refuses. Two further
    reasons not to refuse: the live suite already records 6 of 87 source bindings and finalizes 2 of
    25 markers with an empty set, using the machinery as scaffolding without caring about scope; and
    the harm here is a wasted human signature, not an unreviewed landing. This exact sequence cost
    the repository owner two extra signatures landing ORD-0035.
    """
    if prod:
        return None
    hint = ("  You did not pass --sha. On an integration branch that compares the branch with\n"
            "  itself; pass --sha <branch tip> so the binding covers the change under review.\n"
            if not sha else
            f"  --sha {sha} resolved to a range containing no production files.\n")
    message = (
        f"review-gate: WARNING -- this {what} binds NO production files and can authorize nothing.\n"
        + hint
        + "  Do not collect a signature for it: check --staged will refuse it as a production\n"
          "  content mismatch after the signature has been spent. (backlog P1-15)"
    )
    print(message, file=sys.stderr)
    return message


def _cmd_record_v1(args) -> int:
    required = {
        "run_id": args.run_id,
        "author_invocation_id": args.author_invocation_id,
        "reviewer_invocation_id": args.reviewer_invocation_id,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        print(f"✗ record blocked: v1 requires {', '.join(missing)}")
        return 2
    try:
        source, prod = _v1_source(args.sha)
        source = SourceBinding(**{**source.__dict__, "policy_version": args.policy_version})
        summary = _resolve_summary(args, max_len=1024)
        result = {
            "schema_version": "1.0.0",
            "run_id": args.run_id,
            "author_invocation_id": args.author_invocation_id,
            "reviewer_invocation_id": args.reviewer_invocation_id,
            "repository_id": source.repository_id,
            "branch": source.branch,
            "base_sha": source.base_sha,
            "reviewed_tip_sha": source.reviewed_tip_sha,
            "policy_version": source.policy_version,
            "verdict": args.verdict,
            "summary": summary,
            "production_entries": prod,
            "findings": _load_findings(args.findings_file),
            "recorded_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        }
        path = _v1_store().write_result(result)
    except ReviewStateError as exc:
        print(f"✗ record blocked: {exc}")
        return 2
    print(f"✓ immutable review result created: {args.verdict} @ {source.reviewed_tip_sha[:8]} → {path}")
    _warn_if_binding_is_empty(prod, "review result", args.sha)
    return 0


def cmd_record(args) -> int:
    if args.migration_version == "v0":
        if not ALLOW_LEGACY_WRITES_FOR_TESTS:
            print("✗ record blocked: v0 is a read-only migration adapter")
            return 2
        return _cmd_record_v0(args)
    return _cmd_record_v1(args)


def cmd_finalize(args) -> int:
    reviewer_ids = tuple(item.strip() for item in args.reviewer_invocation_ids.split(",") if item.strip())
    try:
        source, _ = _v1_source(args.sha)
        source = SourceBinding(**{**source.__dict__, "policy_version": args.policy_version})
        expected = None if args.expected_prior_digest == "absent" else args.expected_prior_digest
        marker = _v1_store().finalize(
            run_id=args.run_id,
            author_invocation_id=args.author_invocation_id,
            reviewer_invocation_ids=reviewer_ids,
            finalized_by=args.finalized_by,
            source=source,
            finalized_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            expected_prior_digest=expected,
        )
    except (ReviewStateError, OSError) as exc:
        print(f"✗ finalize blocked: {exc}")
        return 2
    _warn_if_binding_is_empty(
        marker.get("production_entries") if isinstance(marker, dict) else None,
        "final marker", args.sha)
    print(
        f"✓ final marker v{marker['schema_version']} created: "
        f"{marker['verdict']} for run {args.run_id}"
    )
    return 0


def _v1_scope(args) -> tuple[list[str] | None, SourceBinding | None, str, bool]:
    if getattr(args, "pre_commit", False) or getattr(args, "staged", False):
        if _lease_bound_feature_staged_context():
            return [], None, "lease-bound isolated feature staged commit/merge", True
    if getattr(args, "pre_commit", False):
        args.staged = True
    if args.staged:
        cur = _git("rev-parse", "--abbrev-ref", "HEAD")
        db = _default_branch()
        if not cur or cur in (db, "HEAD"):
            staged_files = _git("ls-files", "--stage")
            if staged_files is None:
                raise ReviewStateError("cannot inspect staged index files (fail-closed)")
            for ln in staged_files.splitlines():
                if "\t" in ln:
                    p = ln.split("\t", 1)[1].strip()
                    if _is_root_run_state(p):
                        raise ReviewStateError(
                            f"root run-state file '{p}' cannot land on default branch "
                            f"(DEV_TEAM_RUN*.md and DEV_TEAM_SPEC*.md must be deleted before merge; see skills/dev-team/SKILL.md)"
                        )
        prod = _staged_prod()
        return prod, None, "staged merge/commit", False
    source, prod = _v1_source(args.target)
    source = SourceBinding(**{**source.__dict__, "policy_version": args.policy_version})
    return prod, source, f"{source.branch}@{source.reviewed_tip_sha[:8]}", False


def _candidate_run_ids(requested: str) -> list[str]:
    if requested:
        return [requested]
    if not RUNS_ROOT.is_dir():
        return []
    return sorted(path.name for path in RUNS_ROOT.iterdir() if path.is_dir())


def _linked_feature_stores() -> list[tuple[ReviewStateStore, str, str]]:
    """Discover only live linked-worktree marker stores with exact branch/tip proof.

    Pre-merge hooks cannot portably rely on ``MERGE_HEAD``.  Instead the marker's
    content binding remains the landing proof, while its source branch and tip
    must exactly match an attached linked worktree.  Any parse or Git failure is
    ignored here; the caller has no eligible marker and therefore fails closed.
    """
    # An inherited GIT_DIR overrides ``-C``, so every probe below would answer for the
    # INVOKING repository instead of the worktree under test (P0-22).  The hooks' own
    # ``unset GIT_WORK_TREE GIT_DIR`` does not make this redundant: the gate is equally
    # reachable through a plain CLI run, which scrubs nothing at all, so the strip has to be
    # repeated at the probes themselves.  (Corrected by ORD-0034: this used to say the launcher
    # scrubs nothing either.  As of ORD-0034 scripts/trusted_gate_launcher.ps1 DOES remove
    # GIT_DIR, before its first git call.  The conclusion is unchanged -- the plain CLI path
    # alone is enough to require the strip here -- but the premise was half false and sat in a
    # TRUSTED_BUNDLE_FILES member describing the very file that round edited.)
    # GIT_INDEX_FILE is never stripped -- not here, not in the hooks -- because ORD-0031's B3
    # measured what stripping it costs: ``git commit --only`` runs the gate against a temporary
    # index that Git points GIT_INDEX_FILE at, so dropping the variable sends index reads back
    # to .git/index and an unreviewed file lands unseen
    # (tests/test_review_gate_v1.py::test_git_commit_only_partial_index_goes_blind_if_git_index_file_is_stripped).
    probe_env = dict(os.environ)
    probe_env.pop("GIT_DIR", None)
    try:
        listed = subprocess.run(
            [_TRUSTED_GIT, "-C", str(ROOT), "worktree", "list", "--porcelain"],
            capture_output=True, text=True, encoding="utf-8", check=True, env=probe_env,
        ).stdout.splitlines()
    except (OSError, subprocess.SubprocessError):
        return []
    entries: list[tuple[Path, str]] = []
    path: Path | None = None
    branch: str | None = None
    for line in [*listed, ""]:
        if line.startswith("worktree "):
            path = Path(line.removeprefix("worktree ")).resolve()
        elif line.startswith("branch refs/heads/"):
            branch = line.removeprefix("branch refs/heads/")
        elif not line:
            if path is not None and branch and path != ROOT.resolve():
                entries.append((path, branch))
            path, branch = None, None
    stores: list[tuple[ReviewStateStore, str, str]] = []
    # The trusted anchor every probe below is validated against, so it must be read with the SAME
    # scrubbed environment.  resolve_common_dir() cannot be used here: it delegates to
    # workspace._git(), which passes no env= and so would answer for the INVOKING repository --
    # leaving `common` pointing at one repository while the probes correctly answer for another,
    # which excludes legitimate already-reviewed markers (P0-22).
    try:
        common = Path(subprocess.run(
            [_TRUSTED_GIT, "-C", str(ROOT), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True, text=True, encoding="utf-8", check=True, env=probe_env,
        ).stdout.strip()).resolve(strict=True)
    except (OSError, subprocess.SubprocessError):
        return []
    for worktree, branch in entries:
        try:
            runs_root = worktree / ".devteam" / "runs"
            if not runs_root.is_dir():
                continue
            observed_common = subprocess.run(
                [_TRUSTED_GIT, "-C", str(worktree), "rev-parse", "--path-format=absolute", "--git-common-dir"],
                capture_output=True, text=True, encoding="utf-8", check=True, env=probe_env,
            ).stdout.strip()
            tip = subprocess.run(
                [_TRUSTED_GIT, "-C", str(worktree), "rev-parse", "HEAD"],
                capture_output=True, text=True, encoding="utf-8", check=True, env=probe_env,
            ).stdout.strip()
            git_dir = subprocess.run(
                [_TRUSTED_GIT, "-C", str(worktree), "rev-parse", "--path-format=absolute", "--git-dir"],
                capture_output=True, text=True, encoding="utf-8", check=True, env=probe_env,
            ).stdout.strip()
            symbolic_branch = subprocess.run(
                [_TRUSTED_GIT, "-C", str(worktree), "symbolic-ref", "--quiet", "--short", "HEAD"],
                capture_output=True, text=True, encoding="utf-8", check=True, env=probe_env,
            ).stdout.strip()
            ref_tip = subprocess.run(
                [_TRUSTED_GIT, "-C", str(worktree), "rev-parse", "--verify", "-q", f"refs/heads/{branch}^{{commit}}"],
                capture_output=True, text=True, encoding="utf-8", check=True, env=probe_env,
            ).stdout.strip()
            worktrees_namespace = common / "worktrees"
            if (
                Path(observed_common).resolve() != common
                or not Path(git_dir).resolve().is_relative_to(worktrees_namespace)
                or symbolic_branch != branch
                or not tip
                or ref_tip != tip
            ):
                continue
            stores.append((ReviewStateStore(runs_root, CONTRACT_DIRECTORY), branch, tip))
        except (OSError, ValueError, subprocess.SubprocessError, ReviewStateError):
            continue
    return stores


def _security_attestation_paths(
    store: ReviewStateStore,
    run_id: str,
    reviewer_invocation_id: str,
) -> tuple[Path, Path]:
    directory = store.identity_path(run_id, reviewer_invocation_id).parent
    return directory / "review-attestation.json", directory / "review-attestation.json.sig"


def _parse_security_attestation(payload: bytes) -> dict[str, str]:
    # Takes already-read bytes (never re-reads the file itself): the caller reads the attestation
    # payload from disk exactly once and passes the SAME bytes here and to signature verification.
    # A prior version took a Path and read it twice independently -- since the file lives under the
    # attacker-writable candidate worktree, a concurrent writer could present different content to
    # each read, so a signature genuinely covering ONE payload could validate fields taken from a
    # DIFFERENT one (TOCTOU, cross-model review).
    required = {
        "schema_version",
        "platform",
        "session_id",
        "attestor",
        "reviewer_invocation_id",
        "provider",
        "model",
        "reviewed_tip_sha",
        "review_verdict",
        "review_result_sha256",
        "issued_at",
    }
    try:
        value = json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewStateError(f"security attestation cannot be loaded: {exc}") from exc
    if not isinstance(value, dict) or set(value) != required:
        raise ReviewStateError("security attestation has an invalid field set")
    if not all(isinstance(item, str) and item for item in value.values()):
        raise ReviewStateError("security attestation fields must be non-empty strings")
    if value["schema_version"] != _SECURITY_ATTESTATION_SCHEMA_VERSION:
        raise ReviewStateError("security attestation schema version is unsupported")
    if len(value["platform"]) > 64 or len(value["session_id"]) > 256:
        raise ReviewStateError("security attestation platform or session ID is oversized")
    if len(value["attestor"]) > 128 or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._@-"
        for character in value["attestor"]
    ):
        raise ReviewStateError("security attestation attestor is invalid")
    if len(value["review_result_sha256"]) != 64 or any(
        character not in "0123456789abcdef" for character in value["review_result_sha256"]
    ):
        raise ReviewStateError("security attestation result digest is invalid")
    if len(value["reviewed_tip_sha"]) not in (40, 64) or any(
        character not in "0123456789abcdef" for character in value["reviewed_tip_sha"]
    ):
        raise ReviewStateError("security attestation reviewed tip is invalid")
    if value["review_verdict"] not in _ALL_VERDICTS:
        raise ReviewStateError("security attestation review verdict is invalid")
    try:
        datetime.fromisoformat(value["issued_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise ReviewStateError("security attestation timestamp is invalid") from exc
    return value


def _verify_security_attestation_signature(
    payload: bytes,
    signature_path: Path,
    attestor: str,
) -> str | None:
    signers = POLICY_ROOT / _SECURITY_ATTESTATION_SIGNERS
    executable = _trusted_ssh_keygen()
    if executable is None:
        return "ssh-keygen is unavailable for security attestation verification"
    if not signers.is_file() or not signature_path.is_file():
        return "security attestation signer configuration or signature is missing"
    try:
        result = subprocess.run(
            [
                executable,
                "-Y",
                "verify",
                "-f",
                str(signers),
                "-I",
                attestor,
                "-n",
                _SECURITY_ATTESTATION_NAMESPACE,
                "-s",
                str(signature_path),
            ],
            input=payload,
            capture_output=True,
            check=False,
        )
    except OSError as exc:
        return f"security attestation signature verification cannot run: {exc}"
    if result.returncode != 0:
        return "security attestation signature verification failed"
    return None


def _trusted_ssh_keygen() -> str | None:
    """Resolve the verifier dynamically or via AI_COMPANY_SSH_KEYGEN_BIN override, failing closed if unavailable."""
    override = os.environ.get("AI_COMPANY_SSH_KEYGEN_BIN")
    if override:
        candidate = Path(override).expanduser().resolve()
        if candidate.is_file():
            return str(candidate)
        return None
    discovered = _safe_which("ssh-keygen", excluded_roots=(ROOT,))
    if discovered:
        return str(Path(discovered).resolve())
    return None


def _security_reviewer_attestation_eligible(
    store: ReviewStateStore,
    run_id: str,
    reviewer_id: str,
    identity: dict[str, object],
    marker_source: SourceBinding,
) -> tuple[str | None, str | None]:
    payload_path, signature_path = _security_attestation_paths(store, run_id, reviewer_id)
    if not signature_path.is_file():
        return None, "security attestation signature is missing"
    try:
        payload = payload_path.read_bytes()
    except OSError as exc:
        return None, f"security attestation cannot be loaded: {exc}"
    attestation = _parse_security_attestation(payload)
    expected = {
        "reviewer_invocation_id": reviewer_id,
        "provider": str(identity["provider"]),
        "model": str(identity["model"]),
        "reviewed_tip_sha": marker_source.reviewed_tip_sha,
        "review_verdict": str(store.read_result(run_id, reviewer_id)["verdict"]),
        "review_result_sha256": hashlib.sha256(
            store.result_path(run_id, reviewer_id).read_bytes()
        ).hexdigest(),
    }
    for field, value in expected.items():
        if attestation[field] != value:
            return None, f"security attestation {field} mismatch"
    signature_error = _verify_security_attestation_signature(
        payload, signature_path, attestation["attestor"]
    )
    if signature_error is not None:
        return None, signature_error
    return attestation["session_id"], None


def _is_terminal_lifecycle_successor(reviewed_tip: str, feature_tip: str) -> bool:
    """Allow only the mandated journal-then-cleanup pair after a reviewed feature tip.

    A linked worktree normally has to remain exactly at the marker's reviewed tip, so an
    arbitrary post-review commit cannot reuse the marker.  Stage 3 is the single exception:
    it must append durable telemetry and then remove the two root working artifacts before
    landing.  Prove that exact two-commit chain rather than trusting a commit subject or a
    content subset, both of which an unrelated post-review commit could imitate.
    """
    if _git("merge-base", reviewed_tip, feature_tip) != reviewed_tip:
        return False
    span = _git("rev-list", "--reverse", f"{reviewed_tip}..{feature_tip}")
    if span is None:
        return False
    commits = [item for item in span.splitlines() if item]
    if len(commits) != 2:
        return False
    journal_commit, cleanup_commit = commits
    if _git("show", "-s", "--format=%P", journal_commit) != reviewed_tip:
        return False
    if _git("show", "-s", "--format=%P", cleanup_commit) != journal_commit:
        return False

    def changed_paths(commit: str) -> list[tuple[str, str]] | None:
        output = _git("show", "--format=", "--name-status", "--no-renames", commit)
        if output is None:
            return None
        paths: list[tuple[str, str]] = []
        for line in output.splitlines():
            fields = line.split("\t", 1)
            if len(fields) != 2:
                return None
            paths.append((fields[0], fields[1]))
        return paths

    journal_paths = changed_paths(journal_commit)
    cleanup_paths = changed_paths(cleanup_commit)
    if journal_paths is None or cleanup_paths is None:
        return False
    journal_files = {path for status, path in journal_paths if status in {"A", "M"}}
    if (
        len(journal_paths) != 2
        or len(journal_files) != 2
        or "ops/ORDERS.md" not in journal_files
        or sum(path.startswith("ops/journal/") and path.endswith(".jsonl") for path in journal_files) != 1
    ):
        return False
    return set(cleanup_paths) == {
        ("D", "DEV_TEAM_RUN.md"),
        ("D", "DEV_TEAM_SPEC.md"),
    }


def _v1_marker_eligible(
    store: ReviewStateStore,
    run_id: str,
    prod: list[str],
    source: SourceBinding | None,
    policy_version: str,
    expected_feature: tuple[str, str] | None = None,
) -> tuple[bool, str]:
    try:
        raw = json.loads(store.marker_path(run_id).read_text(encoding="utf-8"))
        marker_source = SourceBinding(
            repository_id=str(raw["repository_id"]),
            branch=str(raw["branch"]),
            base_sha=str(raw["base_sha"]),
            reviewed_tip_sha=str(raw["reviewed_tip_sha"]),
            policy_version=str(raw["policy_version"]),
        )
        marker = store.verify_marker(run_id, marker_source)
        current_repository = _repository_id(resolve_common_dir(ROOT))
        if marker_source.repository_id != current_repository:
            return False, "repository mismatch"
        if marker_source.policy_version != policy_version:
            return False, "policy-version mismatch"
        if expected_feature is not None:
            expected_branch, expected_tip = expected_feature
            if marker_source.branch != expected_branch:
                return False, "linked worktree branch/tip mismatch"
            if (
                marker_source.reviewed_tip_sha != expected_tip
                and not _is_terminal_lifecycle_successor(
                    marker_source.reviewed_tip_sha, expected_tip
                )
            ):
                return False, "linked worktree branch/tip mismatch"
        if source is not None and marker_source != source:
            return False, "branch/base/tip/policy mismatch"
        if source is None and marker_source.base_sha != _head():
            return False, "staged base mismatch"
        if marker["verdict"] not in _OK_VERDICTS:
            return False, "non-accepting verdict"
        if any(entry not in set(marker["production_entries"]) for entry in prod):
            return False, "production content mismatch"
        if _is_security_surface(_paths(prod)):
            reviewer_ids = (
                marker["reviewer_invocation_ids"]
                if marker["schema_version"] == "1.0.0"
                else [entry["invocation_id"] for entry in marker["reviewers"]]
            )
            required = _required_security_reviewers(_paths(prod))
            if len(reviewer_ids) < required or len(set(reviewer_ids)) != len(reviewer_ids):
                return False, (
                    f"security review requires {required} independent approved reviewer "
                    f"invocation(s) with distinct ids"
                    + (f" -- {_dual_review_reason(_paths(prod))}"
                       if required == _SECURITY_REVIEWER_DUAL else "")
                )
            session_ids: set[str] = set()
            for reviewer_id in reviewer_ids:
                identity = store.read_identity(run_id, reviewer_id)
                provider_model = (str(identity["provider"]), str(identity["model"]))
                if provider_model not in _SECURITY_REVIEWER_MODELS:
                    return False, "security reviewer provider/model is not approved"
                session_id, attestation_error = _security_reviewer_attestation_eligible(
                    store, run_id, reviewer_id, identity, marker_source
                )
                if attestation_error is not None:
                    return False, attestation_error
                if session_id in session_ids:
                    return False, "security reviewers must have distinct attested sessions"
                session_ids.add(session_id)
        return True, "eligible"
    except (OSError, ValueError, KeyError, ReviewStateError) as exc:
        return False, str(exc)


def _cmd_check_v1(args) -> int:
    try:
        prod, source, why, exempt = _v1_scope(args)
    except ReviewStateError as exc:
        print(f"✗ review-gate blocked: {exc}")
        return 1
    if prod is None:
        print("✗ review-gate blocked: production diff cannot be resolved")
        return 1
    if exempt or not prod:
        print(f"review-gate: no v1 review required ({why})")
        return 0
    reasons = []
    eligible_runs: list[tuple[Path, str]] = []
    authorizing_digests: set[str] = set()
    stores: list[tuple[ReviewStateStore, tuple[str, str] | None]] = [(_v1_store(), None)]
    if source is None and not args.run_id:
        stores.extend((store, (branch, tip)) for store, branch, tip in _linked_feature_stores())
    for store, expected_feature in stores:
        candidate_ids = [args.run_id] if args.run_id else (
            sorted(path.name for path in store.root.iterdir() if path.is_dir()) if store.root.is_dir() else []
        )
        for run_id in candidate_ids:
            eligible, reason = _v1_marker_eligible(
                store, run_id, prod, source, args.policy_version, expected_feature
            )
            if not eligible:
                reasons.append(f"{run_id}: {reason}")
                continue
            # The SAME immutable marker legitimately appears in more than one store when
            # `.devteam/runs/<run_id>` is copied between a still-attached linked worktree and the
            # primary (the documented consumer-adoption flow). Content-digest dedup collapses that
            # into one authorization; a genuinely different marker (different reviewed_tip_sha, e.g.
            # two independently reviewed sibling worktrees) has different bytes and stays distinct,
            # so real ambiguity still blocks.
            try:
                digest = hashlib.sha256(store.marker_path(run_id).read_bytes()).hexdigest()
            except OSError as exc:
                reasons.append(f"{run_id}: marker unreadable for dedup: {exc}")
                continue
            if digest in authorizing_digests:
                continue
            authorizing_digests.add(digest)
            eligible_runs.append((store.root, run_id))
    if len(eligible_runs) == 1:
        authorizing_root, authorizing_run = eligible_runs[0]
        print(
            f"✓ review-gate v1 passed: run={authorizing_run}, store={authorizing_root}, "
            f"files={len(prod)}, scope={why}"
        )
        return 0
    if len(eligible_runs) > 1:
        reasons.append(
            "ambiguous eligible run-scoped final markers: "
            + ", ".join(f"{root}::{run_id}" for root, run_id in sorted(eligible_runs, key=str))
        )
    print(f"✗ review-gate v1 blocked: no eligible run-scoped final marker ({why})")
    if reasons:
        print("  " + "; ".join(reasons[:5]))
    return 1


def _warn_if_running_gate_is_stale() -> str | None:
    """Say so, loudly, when the gate now executing is not the source in the target working tree.

    P0-46, measured live: hours after ORD-0035 merged and pushed, the pinned bundle was still an
    INTERMEDIATE commit of that order's own branch. Ten files that two cold panels had established
    are load-bearing for fail-closed controls -- the PreToolUse guard wiring, ``policy/``,
    ``providers/``, ``scripts/external_review.py``, ``docs/ACCEPTED_REVIEW_RESIDUALS.md`` and the
    agent carve-out ``D-20260824-004`` ruled out -- returned ONE reviewer in the RUNNING gate while
    the reviewed, attested, signed and merged source said TWO. Merging a change to a trusted-bundle
    member does not put it into effect; only reinstalling does. It was found by accident.

    WARNS, never refuses, and the distinction is structural rather than cautious: the merge that
    updates the bundle must itself be allowed to land, so a gate that refused on its own staleness
    would deadlock the only commit that can fix it.

    Silent when the comparison cannot be made, and the reason stated here was wrong the first time
    a reviewer checked it. It said consumer repositories "do not contain the framework's own
    source", which `config/review_gate_distribution.json` contradicts: its `install_files` list is a
    strict superset of `_TRUSTED_BUNDLE_FILES`, so all sixteen members DO ship to consumers. The
    real cases the silence is for are a repository that never installed the gate, a partially
    installed one, and an unreadable file -- measured to be silent in all three, plus a repository
    that installed it and then upgraded, which correctly warns. The behaviour was right; only this
    paragraph was not.
    """
    try:
        if POLICY_ROOT.resolve() == ROOT.resolve():
            return None          # running from the repo itself; there is no installed copy to differ
        # P1-16 / P1-17: compare normalised digests so git CRLF/LF rewriting does not fire a false staleness warning
        running = trusted_bundle_digest(normalise_newlines=True)          # the bundle this process is executing from
        tracked = trusted_bundle_digest(ROOT, normalise_newlines=True)      # the same files in the target working tree
    except (OSError, ReviewStateError, ValueError):
        return None
    if running == tracked:
        return None
    message = (
        "review-gate: WARNING -- the gate now running is NOT the source in this working tree.\n"
        f"  running from : {running[:16]}\n"
        f"  working tree : {tracked[:16]}\n"
        "  A change to a trusted-bundle member is INERT until the bundle is reinstalled, so a\n"
        "  reviewed and merged correction can sit unenforced. After this lands, run:\n"
        "    python scripts/install_hooks.py\n"
        "  (backlog P0-46; scripts/verify-hook-integrity.ps1 reports the same condition.)"
    )
    print(message, file=sys.stderr)
    return message


def cmd_check(args) -> int:
    _warn_if_running_gate_is_stale()
    if args.migration_version == "v0":
        return _cmd_check_v0(args)
    return _cmd_check_v1(args)


def _scrub_process_environment() -> str | None:
    """Remove GIT_DIR from THIS process's environment, once, before any scope decision (B17).

    ORD-0034 first closed P0-26 with a per-call scrub -- ``_git()`` passing ``env=_read_env()``.
    That is necessary but NOT sufficient, and the gap is structural rather than an oversight:
    ``_v1_scope`` consults ``_lease_bound_feature_staged_context()`` BEFORE any staged read, and a
    True there exits 0 with no marker required. That path reaches Git via
    ``runtime/orchestrator/workspace.py``'s ``_git()`` and two inline ``subprocess.run`` calls in
    ``workspace_cli.py``, none of which pass ``env=``. A per-call scrub in THIS module cannot reach
    them by construction, so an inherited GIT_DIR flipped the "worktree is primary rather than a
    dedicated linked worktree" guard from REJECT to ACCEPT and the gate passed an unreviewed staged
    production change. Found by ORD-0034's own panel and reproduced end to end (backlog P0-37).

    Scrubbing at the process boundary closes it WITHOUT editing workspace.py -- a frozen non-goal
    (B20) -- because those call sites read ``os.environ`` at call time and therefore inherit
    whatever this leaves behind.

    This does NOT replace ``_read_env()`` (B19), and the reason is stronger than defence in depth
    -- there is a LIVE CONSUMER that never reaches this function. ``scripts/requirements_gate.py``
    imports this module and calls ``_git``, ``_head``, ``_default_branch`` and ``_branch_prod``
    directly, never entering ``main()``, and performs no scrub of its own. **On that route the
    per-call ``env=_read_env()`` is the ONLY GIT_DIR protection there is.** Found by ORD-0034's
    panel; recorded here so a later round cannot "simplify" the per-call layer away on the belief
    that the startup scrub covers everything. A future edit dropping ``env=_read_env()`` must also
    still turn a test red, and the suite proves each layer independently.

    GIT_INDEX_FILE is NOT removed here (B21), on the same measured grounds as B16: ORD-0031's B3
    showed that stripping it sends index reads back to .git/index and lets a partial-index commit
    through unseen. GIT_COMMON_DIR and GIT_WORK_TREE are untouched (B20) -- P0-27 and P0-28.

    Returns the removed value, or None. ``main()`` reports it on stderr rather than discarding it:
    a silently normalised poison is indistinguishable to an operator from a clean run, and
    ``✓ review-gate v1 passed`` should not be the only thing a redirected invocation prints.
    """
    return os.environ.pop("GIT_DIR", None)


def main(argv=None) -> int:
    # B17: before ANY scope decision, including the lease exemption that runs ahead of
    # every scrubbed read. See _scrub_process_environment for why a per-call scrub alone
    # cannot reach that path.
    _removed_git_dir = _scrub_process_environment()
    if _removed_git_dir is not None:
        # Not a failure -- the scrub did its job. But an operator reading a PASS must be able to
        # tell that this invocation arrived carrying a redirect (ORD-0034 panel, LOW-1).
        print(f"review-gate: removed an inherited GIT_DIR={_removed_git_dir!r} "
              f"before reading anything (ORD-0034 B17)", file=sys.stderr)
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    identity = sub.add_parser("identity-issue", help="Orchestrator creates one immutable v1 identity")
    identity.add_argument("--run-id", required=True)
    identity.add_argument("--invocation-id", required=True)
    identity.add_argument("--role", required=True)
    identity.add_argument("--provider", required=True)
    identity.add_argument("--model", required=True)
    identity.add_argument("--runner-instance-id", required=True)
    identity.set_defaults(func=cmd_identity_issue)

    trusted_bundle = sub.add_parser(
        "trusted-bundle-check",
        help="Verify the installed trusted review-gate bundle digest",
    )
    trusted_bundle.add_argument("--expected-digest", required=True)
    trusted_bundle.set_defaults(func=cmd_trusted_bundle_check)

    attestation_template = sub.add_parser(
        "attestation-template",
        help="Create a signable security-review session attestation after a reviewer records its result",
    )
    attestation_template.add_argument("--run-id", required=True)
    attestation_template.add_argument("--reviewer-invocation-id", required=True)
    attestation_template.add_argument("--platform", required=True)
    attestation_template.add_argument("--session-id", required=True)
    attestation_template.add_argument("--attestor", required=True)
    attestation_template.set_defaults(func=cmd_attestation_template)

    attestation_check = sub.add_parser(
        "attestation-check",
        help="Verify a signed security-review session attestation",
    )
    attestation_check.add_argument("--run-id", required=True)
    attestation_check.add_argument("--reviewer-invocation-id", required=True)
    attestation_check.set_defaults(func=cmd_attestation_check)

    r = sub.add_parser("record", help="Reviewer writes its immutable v1 result")
    r.add_argument("--verdict", required=True, choices=_ALL_VERDICTS)
    r.add_argument("--summary", default="")
    r.add_argument("--summary-file", default="", help="Path to file containing reviewer's summary")
    r.add_argument("--reviewer", default="claude-fresh")
    r.add_argument("--sha", default="")
    r.add_argument("--run-id", default="")
    r.add_argument("--author-invocation-id", default="")
    r.add_argument("--reviewer-invocation-id", default="")
    r.add_argument("--policy-version", default="1.2.0")
    r.add_argument("--findings-file", default="")
    r.add_argument("--migration-version", choices=("v1", "v0"), default=DEFAULT_MIGRATION_VERSION)
    r.set_defaults(func=cmd_record)

    finalize = sub.add_parser(
        "finalize", help="Orchestrator atomically finalizes review results into a v2 marker"
    )
    finalize.add_argument("--run-id", required=True)
    finalize.add_argument("--author-invocation-id", required=True)
    finalize.add_argument("--reviewer-invocation-ids", required=True)
    finalize.add_argument("--finalized-by", required=True)
    finalize.add_argument("--policy-version", default="1.2.0")
    finalize.add_argument("--sha", default="")
    finalize.add_argument("--expected-prior-digest", default="absent")
    finalize.set_defaults(func=cmd_finalize)

    c = sub.add_parser("check", help="閘:non-trivial 變更的每個生產檔內容須有 CLEAN marker 涵蓋(fail-closed)")
    c.add_argument("--staged", action="store_true", help="合併/暫存情境:用暫存區內容(pre-merge-commit/pre-commit)")
    c.add_argument("--pre-commit", dest="pre_commit", action="store_true",
                   help="pre-commit hook 用:僅在 commit 落上預設分支或衝突合併(MERGE_HEAD)時走 staged 檢查")
    c.add_argument("--target", default="")
    c.add_argument("--run-id", default="")
    c.add_argument("--policy-version", default="1.2.0")
    c.add_argument("--migration-version", choices=("v1", "v0"), default=DEFAULT_MIGRATION_VERSION)
    c.set_defaults(func=cmd_check)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
