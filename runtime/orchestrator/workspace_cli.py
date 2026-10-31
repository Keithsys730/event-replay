"""Operational CLI for Phase 0A workspace safety.

The CLI persists only an immutable lease pointer in the worktree. The authoritative digest and
generation are always reloaded from the common-directory lease, avoiding a cross-file crash window
between lease renewal and handle-file replacement.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Mapping, Sequence

from .workspace import (
    AuditBaseline,
    ExpectedState,
    LeaseConflict,
    LeaseHandle,
    StaleLeaseRequiresHumanGate,
    StateDriftError,
    WorkspaceError,
    acquire_lease,
    begin_audit,
    capture_expected_state,
    finish_audit,
    load_lease,
    release_lease,
    renew_lease,
    verify_expected_state,
)
from .workspace import (
    _current_branch,
    _git_dir,
    _lease_path,
    _repository_id,
    _worktree_root,
    resolve_common_dir,
    trusted_git_executable,
)


POINTER_SCHEMA_VERSION = "1.0"


@dataclass(frozen=True)
class LeasePointer:
    schema_version: str
    lease_path: str
    owner: str
    repository_id: str
    integration_branch: str
    worktree: str
    branch: str

    @classmethod
    def from_handle(cls, handle: LeaseHandle) -> "LeasePointer":
        record = handle.record
        return cls(
            schema_version=POINTER_SCHEMA_VERSION,
            lease_path=str(handle.path.resolve(strict=False)),
            owner=record.owner,
            repository_id=record.repository_id,
            integration_branch=record.integration_branch,
            worktree=record.worktree,
            branch=record.branch,
        )

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "LeasePointer":
        required = {field.name for field in cls.__dataclass_fields__.values()}
        if set(value) != required or any(not isinstance(value[name], str) for name in required):
            raise WorkspaceError("invalid lease-pointer record")
        pointer = cls(**value)  # type: ignore[arg-type]
        if pointer.schema_version != POINTER_SCHEMA_VERSION:
            raise WorkspaceError(f"unsupported lease-pointer schema: {pointer.schema_version!r}")
        if not Path(pointer.lease_path).is_absolute():
            raise WorkspaceError("lease-pointer path must be absolute")
        if not pointer.owner:
            raise WorkspaceError("lease-pointer owner is empty")
        return pointer

    def to_mapping(self) -> dict[str, object]:
        return asdict(self)

    def load_current(self, *, require_active: bool = True) -> LeaseHandle:
        handle = load_lease(
            self.lease_path,
            expected_owner=self.owner,
            require_active=require_active,
        )
        record = handle.record
        differences = []
        for name in ("repository_id", "integration_branch", "worktree", "branch"):
            expected = getattr(self, name)
            observed = getattr(record, name)
            if expected != observed:
                differences.append(f"lease pointer {name}: expected {expected!r}, observed {observed!r}")
        if differences:
            raise StateDriftError(differences)
        return handle


def verify_active_feature_lease(
    repo: str | os.PathLike[str],
    pointer_path: str | os.PathLike[str],
) -> LeaseHandle:
    """Verify that ``repo`` is the exact isolated feature worktree owned by an active lease.

    This is the positive workspace proof shared by the staged review-gate exemption and consumer
    bootstrap. It deliberately accepts only repositories with exactly one conventional integration
    ref (``main`` or ``master``), because those are the only integration names the current gate can
    identify without mutable remote metadata.
    """

    root = _worktree_root(repo)
    pointer_source = Path(pointer_path).resolve(strict=False)
    expected_pointer = root / ".devteam" / "workspace_lease.json"
    if os.path.normcase(str(pointer_source)) != os.path.normcase(str(expected_pointer)):
        raise StateDriftError(
            [f"lease pointer path: expected {expected_pointer!s}, observed {pointer_source!s}"]
        )

    current_branch = _current_branch(root)

    conventional = []
    for branch in ("main", "master"):
        result = subprocess.run(
            [trusted_git_executable(), "-C", str(root), "rev-parse", "--verify", "-q", f"refs/heads/{branch}"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        if result.returncode == 0:
            conventional.append(branch)
        elif result.returncode != 1:
            raise WorkspaceError(f"cannot resolve integration ref {branch!r}")
    if len(conventional) != 1:
        raise WorkspaceError("exactly one local conventional integration ref is required")
    integration_branch = conventional[0]
    if current_branch == integration_branch:
        raise WorkspaceError("integration worktree is not eligible for a feature-worktree lease")

    pointer = _load_pointer(pointer_source)
    handle = pointer.load_current()
    common_dir = resolve_common_dir(root)
    repository_id = _repository_id(common_dir)
    expected_lease = _lease_path(common_dir, repository_id, integration_branch)
    differences = []

    def same_path(left: str | os.PathLike[str], right: str | os.PathLike[str]) -> bool:
        return os.path.normcase(str(Path(left).resolve(strict=False))) == os.path.normcase(
            str(Path(right).resolve(strict=False))
        )

    record = handle.record
    if same_path(_git_dir(root), common_dir):
        differences.append("worktree is primary rather than a dedicated linked worktree")
    if not same_path(record.worktree, root):
        differences.append(f"lease worktree: expected {root!s}, observed {record.worktree!r}")
    if not same_path(handle.path, expected_lease):
        differences.append(
            f"lease path: expected {expected_lease!s}, observed {handle.path!s}"
        )
    if record.repository_id != repository_id:
        differences.append(
            f"repository_id: expected {repository_id!r}, observed {record.repository_id!r}"
        )
    if record.integration_branch != integration_branch:
        differences.append(
            "integration_branch: "
            f"expected {integration_branch!r}, observed {record.integration_branch!r}"
        )
    if record.branch != current_branch:
        differences.append(f"branch: expected {current_branch!r}, observed {record.branch!r}")

    integration_result = subprocess.run(
        [
            trusted_git_executable(),
            "-C",
            str(root),
            "rev-parse",
            "--verify",
            f"refs/heads/{integration_branch}",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    observed_integration = integration_result.stdout.strip()
    if integration_result.returncode != 0:
        differences.append(f"cannot resolve integration ref {integration_branch!r}")
    elif observed_integration != record.expected_base_sha:
        differences.append(
            "integration SHA: "
            f"expected {record.expected_base_sha!r}, observed {observed_integration!r}"
        )
    if differences:
        raise StateDriftError(differences)
    return handle


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _read_object(path: Path) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"cannot read state file {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise WorkspaceError(f"state file is not a JSON object: {path}")
    return value


def _write_new(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    data = _canonical_bytes(value)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise WorkspaceError(f"state file already exists: {path}") from exc
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    except BaseException:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _write_replace(path: Path, value: Mapping[str, object]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(_canonical_bytes(value))
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
    except BaseException:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _write_state(path: Path, value: Mapping[str, object], *, replace_existing: bool) -> None:
    if replace_existing:
        _write_replace(path, value)
    else:
        _write_new(path, value)


def _default_state_path(repo: str, filename: str) -> Path:
    return Path(repo).resolve(strict=False) / ".devteam" / filename


def _pointer_path(args: argparse.Namespace) -> Path:
    value = getattr(args, "pointer", None)
    if value:
        return Path(value).resolve(strict=False)
    if not getattr(args, "repo", None):
        raise WorkspaceError("--pointer is required when --repo is unavailable")
    return _default_state_path(args.repo, "workspace_lease.json")


def _load_pointer(path: Path) -> LeasePointer:
    return LeasePointer.from_mapping(_read_object(path))


def _emit(value: Mapping[str, object]) -> None:
    print(json.dumps(value, sort_keys=True, ensure_ascii=True))


def _lease_view(handle: LeaseHandle) -> dict[str, object]:
    return {
        "lease_path": str(handle.path),
        "digest": handle.digest,
        "record": handle.record.to_mapping(),
    }


def _cmd_lease_acquire(args: argparse.Namespace) -> int:
    pointer_path = _pointer_path(args)
    if pointer_path.exists():
        raise WorkspaceError(f"lease pointer already exists: {pointer_path}")
    handle = acquire_lease(
        args.repo,
        args.integration_branch,
        args.owner,
        args.expected_base_sha,
        ttl_seconds=args.ttl_seconds,
    )
    pointer = LeasePointer.from_handle(handle)
    try:
        _write_new(pointer_path, pointer.to_mapping())
    except BaseException:
        release_lease(handle)
        raise
    _emit({"status": "acquired", "pointer": str(pointer_path), **_lease_view(handle)})
    return 0


def _cmd_lease_status(args: argparse.Namespace) -> int:
    pointer_path = _pointer_path(args)
    handle = _load_pointer(pointer_path).load_current()
    _emit({"status": "active", "pointer": str(pointer_path), **_lease_view(handle)})
    return 0


def _cmd_lease_verify_feature(args: argparse.Namespace) -> int:
    pointer_path = _pointer_path(args)
    handle = verify_active_feature_lease(args.repo, pointer_path)
    _emit({"status": "verified", "pointer": str(pointer_path), **_lease_view(handle)})
    return 0


def _cmd_lease_renew(args: argparse.Namespace) -> int:
    pointer_path = _pointer_path(args)
    current = _load_pointer(pointer_path).load_current()
    renewed = renew_lease(current, ttl_seconds=args.ttl_seconds)
    _emit({"status": "renewed", "pointer": str(pointer_path), **_lease_view(renewed)})
    return 0


def _cmd_lease_release(args: argparse.Namespace) -> int:
    pointer_path = _pointer_path(args)
    current = _load_pointer(pointer_path).load_current(require_active=False)
    release_lease(current)
    try:
        pointer_path.unlink()
    except OSError as exc:
        raise WorkspaceError(
            f"lease released but pointer cleanup failed; remove manually: {pointer_path}: {exc}"
        ) from exc
    _emit({"status": "released", "pointer": str(pointer_path), "lease_path": str(current.path)})
    return 0


def _cmd_state_capture(args: argparse.Namespace) -> int:
    pointer_path = _pointer_path(args)
    handle = _load_pointer(pointer_path).load_current()
    state = capture_expected_state(
        args.repo,
        args.default_branch,
        remote=args.remote,
        lease=handle,
        require_clean=True,
    )
    output = (
        Path(args.output).resolve(strict=False)
        if args.output
        else _default_state_path(args.repo, "expected_state.json")
    )
    _write_state(output, state.to_mapping(), replace_existing=args.replace)
    _emit({"status": "captured", "output": str(output), "state": state.to_mapping()})
    return 0


def _cmd_state_verify(args: argparse.Namespace) -> int:
    source = (
        Path(args.state).resolve(strict=False)
        if args.state
        else _default_state_path(args.repo, "expected_state.json")
    )
    expected = ExpectedState.from_mapping(_read_object(source))
    observed = verify_expected_state(expected, args.repo)
    _emit({"status": "verified", "source": str(source), "observed": observed.to_mapping()})
    return 0


def _cmd_audit_start(args: argparse.Namespace) -> int:
    output = Path(args.output).resolve(strict=False)
    baseline = begin_audit(args.repo)
    _write_state(output, baseline.to_mapping(), replace_existing=args.replace)
    _emit({"status": "started", "output": str(output), "baseline": baseline.to_mapping()})
    return 0


def _cmd_audit_finish(args: argparse.Namespace) -> int:
    source = Path(args.state).resolve(strict=False)
    baseline = AuditBaseline.from_mapping(_read_object(source))
    result = finish_audit(baseline, args.repo)
    _emit({"status": "stable" if result.stable else "drifted", "result": result.to_mapping()})
    return 0 if result.stable else 1


def _add_pointer_argument(parser: argparse.ArgumentParser, *, repo_available: bool) -> None:
    help_text = "lease pointer path"
    if repo_available:
        help_text += " (default: <repo>/.devteam/workspace_lease.json)"
    parser.add_argument("--pointer", help=help_text)


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)

    acquire = subparsers.add_parser("lease-acquire", help="acquire and persist a writer lease pointer")
    acquire.add_argument("--repo", required=True)
    acquire.add_argument("--integration-branch", required=True)
    acquire.add_argument("--owner", required=True)
    acquire.add_argument("--expected-base-sha", required=True)
    acquire.add_argument("--ttl-seconds", type=int, default=900)
    _add_pointer_argument(acquire, repo_available=True)
    acquire.set_defaults(handler=_cmd_lease_acquire)

    for name, handler, help_text in (
        ("lease-status", _cmd_lease_status, "read and validate the authoritative lease"),
        ("lease-release", _cmd_lease_release, "release the exact current lease"),
    ):
        command = subparsers.add_parser(name, help=help_text)
        _add_pointer_argument(command, repo_available=False)
        command.set_defaults(handler=handler)

    renew = subparsers.add_parser("lease-renew", help="renew the authoritative lease")
    _add_pointer_argument(renew, repo_available=False)
    renew.add_argument("--ttl-seconds", type=int, default=900)
    renew.set_defaults(handler=_cmd_lease_renew)

    feature = subparsers.add_parser(
        "lease-verify-feature",
        help="verify an active lease against the exact linked feature worktree",
    )
    feature.add_argument("--repo", required=True)
    _add_pointer_argument(feature, repo_available=True)
    feature.set_defaults(handler=_cmd_lease_verify_feature)

    capture = subparsers.add_parser("state-capture", help="capture live completion state")
    capture.add_argument("--repo", required=True)
    capture.add_argument("--default-branch", required=True)
    capture.add_argument("--remote", default="origin")
    capture.add_argument("--output")
    capture.add_argument("--replace", action="store_true")
    _add_pointer_argument(capture, repo_available=True)
    capture.set_defaults(handler=_cmd_state_capture)

    verify = subparsers.add_parser("state-verify", help="verify a persisted completion state")
    verify.add_argument("--repo", required=True)
    verify.add_argument("--state")
    verify.set_defaults(handler=_cmd_state_verify)

    audit_start = subparsers.add_parser("audit-start", help="persist a read-only audit baseline")
    audit_start.add_argument("--repo", required=True)
    audit_start.add_argument("--output", required=True)
    audit_start.add_argument("--replace", action="store_true")
    audit_start.set_defaults(handler=_cmd_audit_start)

    audit_finish = subparsers.add_parser("audit-finish", help="compare a read-only audit baseline")
    audit_finish.add_argument("--repo", required=True)
    audit_finish.add_argument("--state", required=True)
    audit_finish.set_defaults(handler=_cmd_audit_finish)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (StaleLeaseRequiresHumanGate, LeaseConflict) as exc:
        print(json.dumps({"status": "human_gate", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    except (WorkspaceError, OSError, ValueError) as exc:
        print(json.dumps({"status": "blocked", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
