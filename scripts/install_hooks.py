#!/usr/bin/env python3
"""install_hooks — 把 repo 的 hooks/ 安裝進 .git/hooks/. Grade C, pure stdlib.

Canonical home: ai-company (repatriated from stockforge scripts/install_hooks.py, source commit
e1905a3). This script is repo-agnostic: it installs the CURRENT repo's own hooks/ into the hooks
directory below Git's common directory, so primary and linked worktrees share the same active gate.

.git/hooks/ 不入版本控制,故 hook 原始檔放 repo 的 hooks/,由本腳本複製安裝。
安裝後 git merge --no-ff 會經 cross-model review 閘(pre-merge-commit / 衝突合併走 pre-commit
+ MERGE_HEAD);non-trivial 合併需獨立審查 marker。詳見 ai-company/docs/CROSS_MODEL_REVIEW_HARNESS.md。

Usage: python scripts/install_hooks.py [--python-executable <absolute-cpython-path>]
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 只安裝已知的 git hook 檔名。hooks/ 內另有 Claude Code 的 *.ps1 hook(由 sync.ps1 發佈到
# ~/.claude/hooks/),不得落入 .git/hooks/。
GIT_HOOK_NAMES = ("pre-commit", "pre-merge-commit", "post-merge", "post-commit")
TRUSTED_BUNDLE_FILES = (
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
TRUSTED_BUNDLE_DIRECTORY = ("ai-company-runtime", "t")
TRUSTED_BUNDLE_KEY_LENGTH = 16

# HIGH (cross-model review, round 3): trusted_gate_launcher.ps1 pins the interpreter EXE by
# content blob but never verified the Lib/DLLs directory it points sys.path at -- reviewer B
# proved arbitrary code execution in the trust chain by shadowing a stdlib module (hashlib, used
# by trusted_bundle_digest() itself) the gate actually imports. A full-tree digest of Lib/DLLs was
# measured and rejected: this repo's bound interpreter has 4438 .py files / 61.6 MB, ~82s cold /
# ~2s warm to hash -- unacceptable added latency on every commit. A hand-maintained module list
# was also rejected: exactly the "hand-typed enumeration silently drifts" failure class this
# review has been chasing all session. Instead, the closure is DERIVED by actually running
# review_gate.py's --help path under the bound interpreter with sys.path restricted to exactly
# [Lib, DLLs] (mirroring trusted_gate_launcher.ps1's real bootstrap) and recording every
# stdlib/site-packages module Python actually loaded to service it -- self-updating whenever
# review_gate.py's imports change, at the cost of only covering module-level and argparse-setup
# imports, not every runtime-conditional (e.g. exception-handler-only) import. Measured at ~81
# files / ~2.3 MB / ~54ms to hash for this repo's bound interpreter -- negligible added latency.
#
# HIGH (round 4, TWO independent cold Opus reviewers, same two findings): the sys.modules-only
# closure above still let unreviewed code execute inside the trust boundary while its own digest
# check reported success. (1) sys.modules exposes only a module's __file__ (the .py source); it
# never records __cached__, so a __pycache__/*.pyc -- especially an "unchecked hash-based" pyc,
# which CPython imports with ZERO validation against the source -- runs instead of the pinned
# source, unpinned. (2) sys.modules has no visibility into native code at all: a .pyd's transitive
# DLL dependencies (e.g. DLLs/libcrypto-3.dll, loaded by _hashlib.pyd via
# LOAD_WITH_ALTERED_SEARCH_PATH) and the interpreter runtime itself (python3xy.dll/vcruntime140*.dll
# in the home directory -- not the small python.exe stub ai-company.pythonExecutableBlob pins) are
# invisible and were completely unpinned. Both reviewers reproduced the original hashlib-shadowing
# bypass through these gaps, unchanged by everything below. Closed two ways: (a) the probe now also
# records every closure module's __cached__ path, so a planted/incompatible .pyc fails the digest
# check like any other tampered member -- paired with launching the gate under -B so a legitimately
# stale pyc is never rewritten mid-run and silently drift the pin; (b) rather than trying to
# enumerate native PE import tables, every file directly in DLLs/ and every *.dll directly in the
# home directory are pinned unconditionally (directory-level coverage, not sys.modules-derived) --
# measured ~42 files / ~15 MB / ~60ms added, the same order of magnitude as the original budget.
#
# Round 5 (two FRESH independent cold Opus reviewers, given the accepted-residuals context above
# and explicitly asked not to rubber-stamp): both independently re-reproduced the round-4 HIGHs'
# exploit primitives against isolated interpreter copies and confirmed both are genuinely blocked
# by the real installed launcher; both reached ACCEPT. One reviewer additionally found a real,
# non-blocking MED: the closure had no floor, so a future refactor that stopped importing a module
# at the top level (e.g. moved `import hashlib` into a function) would silently shrink the pinned
# set with no installer error and no test failure -- reopening the exact bypass class this
# mechanism exists to close. See _interpreter_closure_floor_names()/_closure_covers_module() below
# and the same-round SystemExit-code tightening in _INTERPRETER_CLOSURE_PROBE.
_INTERPRETER_CLOSURE_MANIFEST_NAME = "interpreter-closure-manifest.json"
_INTERPRETER_CLOSURE_PROBE = r"""
import json, os, runpy, sys
gate, lib, dlls = sys.argv[1], sys.argv[2], sys.argv[3]
sys.path[:] = [lib, dlls]
os.environ['AI_COMPANY_GATE_TARGET_ROOT'] = lib
sys.argv = [gate, '--help']
try:
    runpy.run_path(gate, run_name='__main__')
except SystemExit as exc:
    if exc.code not in (0, None):
        raise
home = os.path.dirname(lib)
lib_cf = os.path.normcase(lib)
dlls_cf = os.path.normcase(dlls)
closure = set()
def _add(f):
    if not f:
        return
    f = os.path.abspath(f)
    fcf = os.path.normcase(f)
    in_scope = fcf == lib_cf or fcf.startswith(lib_cf + os.sep) or fcf == dlls_cf or fcf.startswith(dlls_cf + os.sep)
    if in_scope and os.path.isfile(f):
        closure.add(os.path.relpath(f, home).replace(os.sep, '/'))
for mod in list(sys.modules.values()):
    _add(getattr(mod, '__file__', None))
    _add(getattr(mod, '__cached__', None))
print(json.dumps(sorted(closure)))
"""


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


def trusted_git_executable() -> str:
    """Resolve Git dynamically or via AI_COMPANY_GIT_BIN override, failing closed if unavailable."""
    override = os.environ.get("AI_COMPANY_GIT_BIN")
    if override:
        candidate = Path(override).expanduser().resolve()
        if candidate.is_file():
            return str(candidate)
        raise ValueError(f"trusted system Git executable is unavailable at AI_COMPANY_GIT_BIN={override!r}")
    discovered = _safe_which("git", excluded_roots=(ROOT,))
    if discovered:
        return str(Path(discovered).resolve())
    raise ValueError("trusted system Git executable is unavailable")


def trusted_bundle_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for relative in TRUSTED_BUNDLE_FILES:
        source = root / relative
        if not source.is_file():
            raise ValueError(f"Trusted bundle source is missing: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        content = source.read_bytes().replace(b"\r\n", b"\n").replace(b"\r", b"\n")
        digest.update(content)
        digest.update(b"\0")
    return digest.hexdigest()


def _interpreter_closure_floor_names(bundle_root: Path) -> set[str]:
    """Top-level stdlib module names the first-party trusted-bundle .py files import at module
    level, derived by AST (never hand-typed) so this floor self-updates with TRUSTED_BUNDLE_FILES's
    own imports instead of silently drifting -- the same principle as the closure derivation
    itself. Excludes CPython's compiled-in builtins (sys.builtin_module_names -- no separate file
    to pin) and the first-party runtime package (covered by trusted_bundle_digest(), not this
    closure)."""
    names: set[str] = set()
    for relative in TRUSTED_BUNDLE_FILES:
        if not relative.endswith(".py"):
            continue
        source = bundle_root / relative
        if not source.is_file():
            continue
        tree = ast.parse(source.read_text(encoding="utf-8"), filename=relative)
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    names.add(alias.name.split(".")[0])
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names.add(node.module.split(".")[0])
    return names - set(sys.builtin_module_names) - {"runtime"}


def _closure_covers_module(closure_set: set[str], name: str) -> bool:
    prefixes = (f"Lib/{name}.", f"Lib/{name}/", f"DLLs/{name}.", f"DLLs/_{name}.")
    return any(entry.startswith(prefix) for entry in closure_set for prefix in prefixes)


def derive_interpreter_closure(python_executable: Path, gate_path: Path) -> list[str]:
    """Run review_gate.py's --help path under the bound interpreter with sys.path restricted to
    exactly [Lib, DLLs] (mirroring trusted_gate_launcher.ps1's real bootstrap), then report every
    stdlib/site-packages module (source and cached bytecode) that was actually imported to service
    it, plus every file directly in DLLs/ and every *.dll directly in the home directory (native
    code sys.modules cannot see), as paths relative to the interpreter's home directory. See the
    module-level comment on _INTERPRETER_CLOSURE_MANIFEST_NAME for what this covers and does not."""
    runtime_home = python_executable.parent
    lib = runtime_home / "Lib"
    dlls = runtime_home / "DLLs"
    probe = subprocess.run(
        [str(python_executable), "-I", "-S", "-B", "-c", _INTERPRETER_CLOSURE_PROBE, str(gate_path), str(lib), str(dlls)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if probe.returncode != 0:
        detail = probe.stderr.strip() or probe.stdout.strip() or f"exit {probe.returncode}"
        raise ValueError(f"cannot derive interpreter module closure: {detail}")
    lines = probe.stdout.strip().splitlines()
    try:
        closure = json.loads(lines[-1]) if lines else None
    except json.JSONDecodeError as exc:
        raise ValueError(f"interpreter module closure probe returned unparseable output: {exc}") from exc
    if not isinstance(closure, list) or not closure or not all(isinstance(item, str) and item for item in closure):
        raise ValueError("interpreter module closure probe returned an empty or invalid list")
    closure_set = set(closure)
    if dlls.is_dir():
        for entry in dlls.iterdir():
            if entry.is_file():
                closure_set.add(f"DLLs/{entry.name}")
    for entry in runtime_home.iterdir():
        if entry.is_file() and entry.suffix.lower() == ".dll":
            closure_set.add(entry.name)
    # MED (round 4c cross-model review, not blocking today but a real regression-safety gap): the
    # closure had no floor, so a future refactor that stopped importing e.g. hashlib at module
    # level would silently shrink the pinned set with no error and no test going red -- reopening
    # the exact bypass class this whole mechanism exists to close. Derive the required floor from
    # what the trusted bundle's own first-party .py files actually import at module level (AST,
    # never hand-typed), and fail loud if the derived closure doesn't cover every one of them.
    bundle_root = gate_path.parent.parent
    missing = sorted(
        name for name in _interpreter_closure_floor_names(bundle_root)
        if not _closure_covers_module(closure_set, name)
    )
    if missing:
        raise ValueError(f"interpreter module closure is missing required members for: {', '.join(missing)}")
    return sorted(closure_set)


def interpreter_closure_digest(runtime_home: Path, manifest_bytes: bytes, closure: list[str]) -> str:
    # The manifest's own bytes are the FIRST entry in the digest chain, so tampering the file list
    # itself (e.g. removing an entry to exempt a tampered module from verification) also
    # invalidates the digest -- the same reasoning as trusted_bundle_digest() over TRUSTED_BUNDLE_FILES.
    digest = hashlib.sha256()
    digest.update(_INTERPRETER_CLOSURE_MANIFEST_NAME.encode("utf-8"))
    digest.update(b"\0")
    digest.update(manifest_bytes)
    digest.update(b"\0")
    for relative in closure:
        source = runtime_home / relative
        if not source.is_file():
            raise ValueError(f"interpreter closure member is missing: {relative}")
        digest.update(relative.encode("utf-8"))
        digest.update(b"\0")
        digest.update(source.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def install_interpreter_closure_manifest(python_executable: Path, gate_path: Path, bundle_root: Path) -> tuple[Path, str]:
    """Derive the interpreter's actually-imported module closure and pin it as a bundle-adjacent
    manifest. Returns (manifest_path, digest); scripts/trusted_gate_launcher.ps1 re-verifies this
    digest, computed independently in PowerShell/.NET (never via this repo's own Python hashlib),
    before it will trust Lib/DLLs enough to launch Python at all."""
    closure = derive_interpreter_closure(python_executable, gate_path)
    manifest_payload = {"schema_version": "1.0.0", "files": closure}
    manifest_bytes = (json.dumps(manifest_payload, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
    runtime_home = python_executable.parent
    digest = interpreter_closure_digest(runtime_home, manifest_bytes, closure)
    manifest_path = bundle_root / _INTERPRETER_CLOSURE_MANIFEST_NAME
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix="", suffix="", dir=manifest_path.parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.write_bytes(manifest_bytes)
        os.replace(temporary, manifest_path)
    finally:
        temporary.unlink(missing_ok=True)
    return manifest_path, digest


def preflight_python_runtime(python_executable: Path, root: Path) -> Path:
    """Reject ambiguous runtimes before the installer modifies hooks or config."""
    executable = python_executable.resolve(strict=False)
    candidate_root = root.resolve(strict=False)
    if not executable.is_file() or not executable.is_absolute():
        raise ValueError(f"Python executable is not an absolute regular file: {executable}")
    try:
        executable.relative_to(candidate_root)
    except ValueError:
        pass
    else:
        raise ValueError("Python executable must not be inside the installation root")

    runtime_home = executable.parent
    startup_files = [runtime_home / "pyvenv.cfg", runtime_home.parent / "pyvenv.cfg"]
    startup_files.extend(runtime_home.glob("*._pth"))
    if any(path.is_file() for path in startup_files):
        raise ValueError("Python runtime has forbidden venv or ._pth startup files")
    if not (runtime_home / "Lib" / "os.py").is_file() or not (runtime_home / "DLLs").is_dir():
        raise ValueError("Python executable is not a canonical CPython runtime")
    probe = subprocess.run(
        [str(executable), "-I", "-S", "-c", "import sys; assert sys.implementation.name == 'cpython'; assert sys.version_info >= (3, 11)"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if probe.returncode != 0:
        detail = probe.stderr.strip() or probe.stdout.strip() or f"exit {probe.returncode}"
        raise ValueError(f"Python runtime isolation probe failed: {detail}")
    return executable


def install_trusted_bundle(root: Path, common_hook_directory: Path) -> tuple[Path, str]:
    digest = trusted_bundle_digest(root)
    # The full digest remains in repository-local configuration and is checked
    # over every bundle file.  Only this directory component is abbreviated to
    # keep deployed hooks within Windows' legacy path limit in deep worktrees.
    bundle_root = common_hook_directory.parent.joinpath(*TRUSTED_BUNDLE_DIRECTORY, digest[:TRUSTED_BUNDLE_KEY_LENGTH])
    for relative in TRUSTED_BUNDLE_FILES:
        source = root / relative
        destination = bundle_root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        if not destination.exists():
            # No prefix/suffix: embedding the destination name (as a prior revision did)
            # made the temporary path longer than the final one, silently reintroducing
            # the Windows MAX_PATH failure the short bundle-directory scheme exists to avoid.
            descriptor, temporary_name = tempfile.mkstemp(prefix="", suffix="", dir=destination.parent)
            os.close(descriptor)
            temporary = Path(temporary_name)
            try:
                shutil.copyfile(source, temporary)
                os.replace(temporary, destination)
            finally:
                temporary.unlink(missing_ok=True)
        if destination.read_bytes() != source.read_bytes():
            raise ValueError(f"Trusted bundle file differs from source: {relative}")
    return bundle_root, digest


def refuse_any_effective_hooks_path(git_executable: str) -> str | None:
    """Return an error when any attached worktree bypasses the common hooks.

    ``extensions.worktreeConfig`` permits one linked worktree to have a
    worktree-local ``core.hooksPath`` while the installation worktree has none.
    The hooks directory is common, so accepting that state would install a gate
    that the integration worktree silently never executes.
    """
    listed = subprocess.run(
        [git_executable, "-C", str(ROOT), "worktree", "list", "--porcelain"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if listed.returncode != 0:
        detail = listed.stderr.strip() or listed.stdout.strip() or f"exit {listed.returncode}"
        return f"Cannot enumerate attached Git worktrees: {detail}"
    worktrees: list[Path] = []
    for line in listed.stdout.splitlines():
        if line.startswith("worktree "):
            path = Path(line.removeprefix("worktree ")).resolve(strict=False)
            if not path.is_dir():
                return f"Cannot verify configured hooksPath in unavailable worktree: {path}"
            worktrees.append(path)
    if not worktrees:
        return "Cannot enumerate attached Git worktrees: no worktree records returned"
    for worktree in worktrees:
        configured = subprocess.run(
            [git_executable, "-C", str(worktree), "config", "--get", "core.hooksPath"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if configured.returncode == 0:
            value = configured.stdout.strip() or "<blank>"
            return f"Refusing installation while effective core.hooksPath is configured in {worktree}: {value}"
        if configured.returncode != 1:
            detail = configured.stderr.strip() or configured.stdout.strip() or f"exit {configured.returncode}"
            return f"Cannot verify effective core.hooksPath in {worktree}: {detail}"
    return None


def main(argv: list[str] | tuple[str, ...] = ()) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python-executable", default=sys.executable)
    args = parser.parse_args(argv)
    python_executable = Path(args.python_executable).resolve(strict=False)
    try:
        python_executable = preflight_python_runtime(python_executable, ROOT)
    except ValueError as exc:
        print(str(exc))
        return 1
    python_config = python_executable.as_posix()
    try:
        git_executable = trusted_git_executable()
    except ValueError as exc:
        print(str(exc))
        return 1

    src = ROOT / "hooks"
    if not src.is_dir():
        print(f"No hooks/ source directory: {src}")
        return 1
    missing_hooks = [name for name in GIT_HOOK_NAMES if not (src / name).is_file()]
    if missing_hooks:
        for name in missing_hooks:
            print(f"Cannot install; managed hook source is missing: {name} ({src / name})")
        return 1

    top_level = subprocess.run(
        [git_executable, "-C", str(ROOT), "rev-parse", "--show-toplevel"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    observed_top = (
        Path(top_level.stdout.strip()).resolve(strict=False)
        if top_level.returncode == 0 and top_level.stdout.strip()
        else None
    )
    fixture_only = False
    if observed_top != ROOT.resolve(strict=False):
        fixture_hooks = ROOT / ".git" / "hooks"
        fixture_head = ROOT / ".git" / "HEAD"
        if fixture_hooks.is_dir() and not fixture_head.exists():
            # Backward-compatible pure-filesystem unit-test seam. It cannot configure or affect a
            # real repository because the fixture has no Git HEAD and no exact top-level binding.
            dst = fixture_hooks
            fixture_only = True
        else:
            detail = (
                f"observed parent repository {observed_top}"
                if observed_top is not None
                else top_level.stderr.strip() or top_level.stdout.strip() or "not a Git worktree"
            )
            print(f"Hook installation root is not the exact Git worktree: {detail}")
            return 1
    else:
        hooks_path_error = refuse_any_effective_hooks_path(git_executable)
        if hooks_path_error is not None:
            print(hooks_path_error)
            return 1
        resolved = subprocess.run(
            [git_executable, "-C", str(ROOT), "rev-parse", "--path-format=absolute", "--git-path", "hooks"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if resolved.returncode != 0 or not resolved.stdout.strip():
            detail = resolved.stderr.strip() or resolved.stdout.strip() or f"exit {resolved.returncode}"
            print(f"Cannot resolve Git common hooks directory: {detail}")
            return 1
        dst = Path(resolved.stdout.strip()).resolve(strict=False)
        common_dir = subprocess.run(
            [git_executable, "-C", str(ROOT), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        expected = Path(common_dir.stdout.strip()).resolve(strict=False) / "hooks"
        if common_dir.returncode != 0 or not common_dir.stdout.strip() or dst != expected:
            print("Refusing installation because hooks are not in the Git common directory")
            return 1
        dst.mkdir(parents=True, exist_ok=True)

    n = 0
    for name in GIT_HOOK_NAMES:
        h = src / name
        target = dst / h.name
        if not target.is_symlink() and target.is_file() and target.read_bytes() == h.read_bytes():
            target.chmod(
                target.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
            )
            print(f"  Already installed {h.name} -> {target}")
            n += 1
            continue
        # No prefix/suffix: the git common hooks directory has no path-shortening of its
        # own, so an embedded-name temp file is the only thing that can push a
        # deep consumer worktree's hook install over Windows' MAX_PATH limit.
        descriptor, temporary_name = tempfile.mkstemp(prefix="", suffix="", dir=dst)
        os.close(descriptor)
        temporary = Path(temporary_name)
        try:
            shutil.copyfile(h, temporary)
            temporary.chmod(
                temporary.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH
            )
            os.replace(temporary, target)
        finally:
            temporary.unlink(missing_ok=True)
        print(f"  Installed {h.name} -> {target}")
        n += 1
    if fixture_only:
        print(f"=== Installed {n} hook(s) into a non-Git filesystem fixture ===")
        return 0
    try:
        trusted_root, trusted_digest = install_trusted_bundle(ROOT, dst)
    except (OSError, ValueError) as exc:
        print(f"Cannot install trusted review-gate bundle: {exc}")
        return 1
    try:
        closure_manifest_path, closure_digest = install_interpreter_closure_manifest(
            python_executable, trusted_root / "scripts" / "review_gate.py", trusted_root
        )
    except (OSError, ValueError) as exc:
        print(f"Cannot pin the interpreter module closure: {exc}")
        return 1
    hashed = subprocess.run(
        [
            git_executable,
            "-C",
            str(ROOT),
            "hash-object",
            "--no-filters",
            "--",
            str(python_executable),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    python_blob = hashed.stdout.strip()
    if hashed.returncode != 0 or not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", python_blob):
        detail = hashed.stderr.strip() or hashed.stdout.strip() or f"exit {hashed.returncode}"
        print(f"Cannot bind Python executable content identity: {detail}")
        return 1
    # 強制 --no-ff:bare `git merge` 不得 fast-forward,否則無 commit、無 hook → 繞過 review gate。
    # repo-local 設定;--ff-only / --no-verify 仍是明示人工 escape(同 --no-verify 等級)。
    configured = subprocess.run(
        [
            git_executable,
            "-C",
            str(ROOT),
            "config",
            "--local",
            "ai-company.pythonExecutableBlob",
            python_blob,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if configured.returncode != 0:
        detail = configured.stderr.strip() or configured.stdout.strip() or f"exit {configured.returncode}"
        print(f"Cannot set repository-local ai-company.pythonExecutableBlob: {detail}")
        return 1
    for key, value in (
        ("ai-company.trustedReviewGatePath", (trusted_root / "scripts" / "review_gate.py").as_posix()),
        ("ai-company.trustedReviewGateDigest", trusted_digest),
        ("ai-company.pythonInterpreterClosureDigest", closure_digest),
    ):
        configured = subprocess.run(
            [git_executable, "-C", str(ROOT), "config", "--local", key, value],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if configured.returncode != 0:
            detail = configured.stderr.strip() or configured.stdout.strip() or f"exit {configured.returncode}"
            print(f"Cannot set repository-local {key}: {detail}")
            return 1
    configured = subprocess.run(
        [
            git_executable,
            "-C",
            str(ROOT),
            "config",
            "--local",
            "ai-company.pythonExecutable",
            python_config,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if configured.returncode != 0:
        detail = configured.stderr.strip() or configured.stdout.strip() or f"exit {configured.returncode}"
        print(f"Cannot set repository-local ai-company.pythonExecutable: {detail}")
        return 1
    configured = subprocess.run(
        [git_executable, "-C", str(ROOT), "config", "--local", "merge.ff", "false"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if configured.returncode != 0:
        detail = configured.stderr.strip() or configured.stdout.strip() or f"exit {configured.returncode}"
        print(f"Cannot set repository-local merge.ff=false: {detail}")
        return 1
    print(f"  Set ai-company.pythonExecutable={python_config}")
    print(f"  Set ai-company.pythonExecutableBlob={python_blob}")
    print(f"  Set ai-company.trustedReviewGatePath={trusted_root / 'scripts' / 'review_gate.py'}")
    print(f"  Set ai-company.trustedReviewGateDigest={trusted_digest}")
    print(f"  Set ai-company.pythonInterpreterClosureDigest={closure_digest} ({closure_manifest_path})")
    print("  Set merge.ff=false (bare git merge always creates a merge commit -> triggers the pre-merge-commit gate)")
    print(f"=== Installed {n} hook(s) + interpreter/config; normal git merge goes through the cross-model review gate ===")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
