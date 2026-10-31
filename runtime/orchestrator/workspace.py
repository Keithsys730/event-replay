"""Phase 0A workspace, lease, baseline, and remote-drift safety.

The primitives in this module are deterministic and provider-neutral. They keep writer leases in a
shared namespace below Git's common directory, bind state to one physical worktree and branch, and
read the live remote SHA instead of trusting a possibly stale remote-tracking ref.

Stale or corrupt lease state is never taken over automatically. Callers must route those cases to the
system's human_gate primitive.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterator, Mapping, Sequence
from urllib.parse import urlsplit


LEASE_SCHEMA_VERSION = "1.0"
STATE_SCHEMA_VERSION = "1.0"
LEASE_NAMESPACE = "ai-company-runtime/leases"
_SHA_RE = re.compile(r"^[0-9a-f]{40,64}$")
_GIT_TIMEOUT_SECONDS = 30
_REMOTE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
_SCP_REMOTE_RE = re.compile(r"^[^@/:\s]+@[^/:\s]+:[^\s]+$")
_READ_ONLY_GIT_SUBCOMMANDS = frozenset({"config", "ls-remote", "rev-parse", "status", "symbolic-ref"})


class WorkspaceError(RuntimeError):
    """Base class for deterministic workspace-safety failures."""


class GitCommandError(WorkspaceError):
    """A required read-only Git query failed or returned malformed output."""


class LeaseConflict(WorkspaceError):
    """Another writer or lease transition currently owns the integration target."""


class StaleLeaseRequiresHumanGate(LeaseConflict):
    """An expired lease exists and may be replaced only after explicit human approval."""


class LeaseOwnershipError(WorkspaceError):
    """The caller does not own the current lease content or supplied a stale digest."""


class StateDriftError(WorkspaceError):
    """Observed repository, worktree, branch, lease, or remote state differs from expectation."""

    def __init__(self, differences: Sequence[str]):
        self.differences = tuple(differences)
        super().__init__("workspace state drift: " + "; ".join(self.differences))


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _ensure_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        raise ValueError("datetime must be timezone-aware")
    return value.astimezone(timezone.utc)


def _utc_text(value: datetime) -> str:
    return _ensure_utc(value).isoformat(timespec="seconds").replace("+00:00", "Z")


def _parse_utc(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (TypeError, ValueError) as exc:
        raise WorkspaceError(f"invalid UTC timestamp: {value!r}") from exc
    return _ensure_utc(parsed)


def _canonical_bytes(value: Mapping[str, object]) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "utf-8"
    )


def _digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _normalized_path(value: str | os.PathLike[str]) -> str:
    return os.path.normcase(str(Path(value).resolve(strict=False)))


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
    """Return the gate-bound Git executable from dynamic system discovery or AI_COMPANY_GIT_BIN override."""
    override = os.environ.get("AI_COMPANY_GIT_BIN") or os.environ.get("AI_COMPANY_TRUSTED_GIT")
    if override:
        candidate = Path(override).expanduser().resolve()
        if candidate.is_file():
            return str(candidate)
        raise GitCommandError(f"trusted system Git executable is unavailable at AI_COMPANY_GIT_BIN={override!r}")
    discovered = _safe_which("git")
    if discovered:
        return str(Path(discovered).resolve())
    raise GitCommandError("trusted system Git executable is unavailable")


def trusted_ssh_executable() -> str:
    """Return the system SSH client used for live remote Git reads."""
    override = os.environ.get("AI_COMPANY_SSH_BIN")
    if override:
        candidate = Path(override).expanduser().resolve()
        if candidate.is_file():
            return str(candidate)
        raise GitCommandError(f"trusted system SSH executable is unavailable at AI_COMPANY_SSH_BIN={override!r}")
    discovered = _safe_which("ssh")
    if discovered:
        return str(Path(discovered).resolve())
    raise GitCommandError("trusted system SSH executable is unavailable")


def _git(
    repo: str | os.PathLike[str],
    *args: str,
    allow_local_file_transport: bool = False,
    isolated_repository: bool = False,
) -> str:
    config_query = (
        len(args) == 4
        and args[:3] == ("config", "--local", "--get")
        and args[3].startswith("remote.")
        and args[3].endswith(".url")
    )
    if (
        not args
        or args[0] not in _READ_ONLY_GIT_SUBCOMMANDS
        or (args[0] == "config" and not config_query)
        or (args[0] == "symbolic-ref" and args[1:] != ("--quiet", "HEAD"))
    ):
        subcommand = args[0] if args else ""
        raise GitCommandError(
            f"Git subcommand is not permitted at the read-only boundary: {subcommand!r}"
        )

    neutral_directory = None
    if isolated_repository:
        try:
            neutral_directory = tempfile.TemporaryDirectory(prefix="ai-company-git-neutral-")
        except OSError as exc:
            raise GitCommandError("unable to create neutral Git execution directory") from exc
        command_repository = neutral_directory.name
    else:
        command_repository = str(repo)
    git_bin = trusted_git_executable()
    command = [git_bin, "-C", command_repository, *args]
    environment = {
        name: value
        for name, value in os.environ.items()
        if (
            not name.upper().startswith("GIT_")
        )
    }
    environment["GIT_TERMINAL_PROMPT"] = "0"
    environment["GIT_CONFIG_NOSYSTEM"] = "1"
    environment["GIT_CONFIG_COUNT"] = "4"
    environment["GIT_CONFIG_KEY_0"] = "protocol.ext.allow"
    environment["GIT_CONFIG_VALUE_0"] = "never"
    environment["GIT_CONFIG_KEY_1"] = "protocol.file.allow"
    environment["GIT_CONFIG_VALUE_1"] = "always" if allow_local_file_transport else "never"
    environment["GIT_CONFIG_KEY_2"] = "credential.helper"
    environment["GIT_CONFIG_VALUE_2"] = ""
    environment["GIT_CONFIG_KEY_3"] = "credential.interactive"
    environment["GIT_CONFIG_VALUE_3"] = "false"
    for name in ("PATH", "HOME", "USERPROFILE", "XDG_CONFIG_HOME", "SSH_ASKPASS"):
        environment.pop(name, None)
    git_dir = str(Path(git_bin).parent)
    if os.name == "nt":
        sys_root = os.environ.get("SystemRoot", r"C:\Windows")
        environment["PATH"] = f"{sys_root}\\System32;{sys_root};{git_dir}"
    else:
        environment["PATH"] = f"/usr/bin:/bin:{git_dir}"
    with tempfile.NamedTemporaryFile(prefix="ai-company-git-config-", delete=False) as config:
        config_path = config.name
    environment["GIT_CONFIG_GLOBAL"] = config_path
    if args[0] == "ls-remote":
        environment["GIT_SSH_COMMAND"] = trusted_ssh_executable()
    try:
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                env=environment,
                timeout=_GIT_TIMEOUT_SECONDS,
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise GitCommandError(f"Git command failed: {type(exc).__name__}") from exc
    finally:
        Path(config_path).unlink(missing_ok=True)
        if neutral_directory is not None:
            neutral_directory.cleanup()
    if result.returncode != 0:
        detail = result.stderr.strip() or result.stdout.strip() or f"exit {result.returncode}"
        raise GitCommandError(f"{' '.join(command)} failed: {detail}")
    return result.stdout.strip()


def resolve_common_dir(repo: str | os.PathLike[str]) -> Path:
    """Return the absolute Git common directory shared by every linked worktree."""

    root = Path(repo).resolve(strict=True)
    raw = _git(root, "rev-parse", "--git-common-dir")
    common = Path(raw)
    if not common.is_absolute():
        common = root / common
    return common.resolve(strict=True)


def _git_dir(repo: str | os.PathLike[str]) -> Path:
    root = Path(repo).resolve(strict=True)
    raw = _git(root, "rev-parse", "--git-dir")
    git_dir = Path(raw)
    if not git_dir.is_absolute():
        git_dir = root / git_dir
    return git_dir.resolve(strict=True)


def _worktree_root(repo: str | os.PathLike[str]) -> Path:
    return Path(_git(repo, "rev-parse", "--show-toplevel")).resolve(strict=True)


def _current_branch(repo: str | os.PathLike[str]) -> str:
    ref = _git(repo, "symbolic-ref", "--quiet", "HEAD")
    prefix = "refs/heads/"
    if not ref.startswith(prefix) or len(ref) == len(prefix):
        raise GitCommandError(f"HEAD is not attached to an exact local branch ref: {ref!r}")
    return ref[len(prefix):]


def _head(repo: str | os.PathLike[str], ref: str = "HEAD") -> str:
    value = _git(repo, "rev-parse", "--verify", ref)
    if not _SHA_RE.fullmatch(value):
        raise GitCommandError(f"git returned malformed SHA for {ref!r}: {value!r}")
    return value


def _is_clean(repo: str | os.PathLike[str]) -> bool:
    return _git(repo, "status", "--porcelain=v1", "--untracked-files=all") == ""


def _repository_id(common_dir: Path) -> str:
    return hashlib.sha256(_normalized_path(common_dir).encode("utf-8")).hexdigest()


def _integration_name(value: str) -> str:
    name = value.removeprefix("refs/heads/").strip()
    if not name or ".." in name or name.startswith("/") or name.endswith("/"):
        raise ValueError(f"invalid integration branch: {value!r}")
    return name


def _lease_path(common_dir: Path, repository_id: str, integration_branch: str) -> Path:
    key = hashlib.sha256(f"{repository_id}\n{integration_branch}\n".encode("utf-8")).hexdigest()
    return common_dir / LEASE_NAMESPACE / f"{key}.json"


@dataclass(frozen=True)
class LeaseRecord:
    schema_version: str
    repository_id: str
    integration_branch: str
    worktree: str
    branch: str
    owner: str
    expected_base_sha: str
    issued_at: str
    heartbeat_at: str
    expires_at: str
    generation: int

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "LeaseRecord":
        required = {field.name for field in cls.__dataclass_fields__.values()}
        if set(value) != required:
            raise WorkspaceError(
                f"invalid lease fields: expected {sorted(required)!r}, observed {sorted(value)!r}"
            )
        try:
            record = cls(**value)  # type: ignore[arg-type]
        except TypeError as exc:
            raise WorkspaceError("invalid lease field types") from exc
        record.validate()
        return record

    def validate(self) -> None:
        string_fields = (
            "schema_version",
            "repository_id",
            "integration_branch",
            "worktree",
            "branch",
            "owner",
            "expected_base_sha",
            "issued_at",
            "heartbeat_at",
            "expires_at",
        )
        if any(not isinstance(getattr(self, name), str) for name in string_fields):
            raise WorkspaceError("lease string field has an invalid type")
        if not isinstance(self.generation, int) or isinstance(self.generation, bool):
            raise WorkspaceError("lease generation must be an integer")
        if self.schema_version != LEASE_SCHEMA_VERSION:
            raise WorkspaceError(f"unsupported lease schema: {self.schema_version!r}")
        if not self.owner.strip():
            raise WorkspaceError("lease owner is empty")
        if not _SHA_RE.fullmatch(self.expected_base_sha):
            raise WorkspaceError("lease expected_base_sha is malformed")
        if self.generation < 1:
            raise WorkspaceError("lease generation must be positive")
        _parse_utc(self.issued_at)
        _parse_utc(self.heartbeat_at)
        if _parse_utc(self.expires_at) <= _parse_utc(self.heartbeat_at):
            raise WorkspaceError("lease expiry must be later than heartbeat")

    def to_bytes(self) -> bytes:
        self.validate()
        return _canonical_bytes(asdict(self))

    def to_mapping(self) -> dict[str, object]:
        self.validate()
        return asdict(self)


@dataclass(frozen=True)
class LeaseHandle:
    path: Path
    digest: str
    record: LeaseRecord


def load_lease(
    path: str | os.PathLike[str],
    *,
    expected_owner: str | None = None,
    require_active: bool = True,
    now: datetime | None = None,
) -> LeaseHandle:
    """Load the current authoritative lease bytes and optionally bind them to one owner."""

    lease_path = Path(path).resolve(strict=False)
    record, _, digest = _read_lease(lease_path)
    if expected_owner is not None and record.owner != expected_owner:
        raise LeaseOwnershipError(
            f"lease owner changed: expected {expected_owner!r}, observed {record.owner!r}"
        )
    if require_active and _parse_utc(record.expires_at) <= _ensure_utc(now or _utc_now()):
        raise StaleLeaseRequiresHumanGate("expired lease requires human_gate")
    return LeaseHandle(path=lease_path, digest=digest, record=record)


def _read_lease(path: Path) -> tuple[LeaseRecord, bytes, str]:
    try:
        data = path.read_bytes()
    except OSError as exc:
        raise WorkspaceError(f"cannot read lease {path}: {exc}") from exc
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise WorkspaceError(f"lease is corrupt and requires human_gate: {path}") from exc
    if not isinstance(value, dict):
        raise WorkspaceError(f"lease is not an object and requires human_gate: {path}")
    return LeaseRecord.from_mapping(value), data, _digest(data)


def _write_exclusive(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError:
        raise
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


def _fsync_directory(path: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


@contextmanager
def _lease_transition_lock(path: Path, owner: str, expected_digest: str) -> Iterator[None]:
    lock_path = path.with_suffix(path.suffix + ".lock")
    lock_data = _canonical_bytes({"owner": owner, "expected_digest": expected_digest})
    try:
        _write_exclusive(lock_path, lock_data)
    except FileExistsError as exc:
        raise LeaseConflict(f"lease transition already active: {lock_path}") from exc
    try:
        yield
    finally:
        try:
            lock_path.unlink()
        except FileNotFoundError:
            pass


def _atomic_replace(path: Path, data: bytes, replace_fn: Callable[[str, str], object] = os.replace) -> None:
    descriptor, temp_name = tempfile.mkstemp(prefix=path.name + ".", suffix=".tmp", dir=path.parent)
    temp_path = Path(temp_name)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        replace_fn(str(temp_path), str(path))
        _fsync_directory(path.parent)
    except BaseException:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def acquire_lease(
    repo: str | os.PathLike[str],
    integration_branch: str,
    owner: str,
    expected_base_sha: str,
    *,
    ttl_seconds: int = 900,
    now: datetime | None = None,
) -> LeaseHandle:
    """Atomically acquire one integration-target lease or fail closed.

    An expired lease raises StaleLeaseRequiresHumanGate and is left byte-identical. This function has
    no automatic takeover path.
    """

    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    if not owner.strip():
        raise ValueError("owner must be non-empty")
    if not _SHA_RE.fullmatch(expected_base_sha):
        raise ValueError("expected_base_sha must be a full hexadecimal Git object ID")
    current = _ensure_utc(now or _utc_now())
    common_dir = resolve_common_dir(repo)
    repository_id = _repository_id(common_dir)
    integration = _integration_name(integration_branch)
    worktree = _worktree_root(repo)
    branch = _current_branch(repo)
    if _normalized_path(_git_dir(repo)) == _normalized_path(common_dir):
        raise StateDriftError(("writer must run from a dedicated linked worktree",))
    if branch == integration:
        raise StateDriftError(("writer branch must differ from the integration branch",))
    observed_base = _head(repo, integration)
    if observed_base != expected_base_sha:
        raise StateDriftError(
            (f"expected base {expected_base_sha} differs from {integration} at {observed_base}",)
        )
    record = LeaseRecord(
        schema_version=LEASE_SCHEMA_VERSION,
        repository_id=repository_id,
        integration_branch=integration,
        worktree=_normalized_path(worktree),
        branch=branch,
        owner=owner,
        expected_base_sha=expected_base_sha,
        issued_at=_utc_text(current),
        heartbeat_at=_utc_text(current),
        expires_at=_utc_text(current + timedelta(seconds=ttl_seconds)),
        generation=1,
    )
    path = _lease_path(common_dir, repository_id, integration)
    data = record.to_bytes()
    try:
        _write_exclusive(path, data)
    except FileExistsError as exc:
        try:
            existing, _, existing_digest = _read_lease(path)
        except WorkspaceError as read_error:
            raise LeaseConflict(
                f"existing lease is unreadable and requires human_gate: {path}"
            ) from read_error
        if _parse_utc(existing.expires_at) <= current:
            raise StaleLeaseRequiresHumanGate(
                f"stale lease {existing_digest} owned by {existing.owner!r} requires human_gate"
            ) from exc
        raise LeaseConflict(
            f"active lease {existing_digest} owned by {existing.owner!r} until {existing.expires_at}"
        ) from exc
    _fsync_directory(path.parent)
    return LeaseHandle(path=path, digest=_digest(data), record=record)


def renew_lease(
    handle: LeaseHandle,
    *,
    ttl_seconds: int = 900,
    now: datetime | None = None,
    replace_fn: Callable[[str, str], object] = os.replace,
) -> LeaseHandle:
    """Renew a lease using an owner/digest compare-and-swap under an exclusive transition lock."""

    if ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be positive")
    current = _ensure_utc(now or _utc_now())
    with _lease_transition_lock(handle.path, handle.record.owner, handle.digest):
        observed, _, observed_digest = _read_lease(handle.path)
        if observed_digest != handle.digest:
            raise LeaseOwnershipError(
                f"lease digest changed: expected {handle.digest}, observed {observed_digest}"
            )
        if observed.owner != handle.record.owner:
            raise LeaseOwnershipError(
                f"lease owner changed: expected {handle.record.owner!r}, observed {observed.owner!r}"
            )
        if _parse_utc(observed.expires_at) <= current:
            raise StaleLeaseRequiresHumanGate("expired lease renewal requires human_gate")
        if current < _parse_utc(observed.heartbeat_at):
            raise StateDriftError(("lease renewal clock moved behind the recorded heartbeat",))
        updated = replace(
            observed,
            heartbeat_at=_utc_text(current),
            expires_at=_utc_text(current + timedelta(seconds=ttl_seconds)),
            generation=observed.generation + 1,
        )
        data = updated.to_bytes()
        _atomic_replace(handle.path, data, replace_fn=replace_fn)
    return LeaseHandle(path=handle.path, digest=_digest(data), record=updated)


def release_lease(handle: LeaseHandle) -> None:
    """Release only the exact owner/digest lease represented by the handle."""

    with _lease_transition_lock(handle.path, handle.record.owner, handle.digest):
        observed, _, observed_digest = _read_lease(handle.path)
        if observed_digest != handle.digest or observed.owner != handle.record.owner:
            raise LeaseOwnershipError("lease changed before release")
        handle.path.unlink()
        _fsync_directory(handle.path.parent)


def _validate_remote_target(value: str, *, allow_local_path: bool) -> tuple[str, bool]:
    target = value.strip()
    if not target or any(ch.isspace() or ord(ch) < 32 for ch in target):
        raise GitCommandError(f"remote must be a single safe URL or path: {value!r}")
    if target.startswith("-") or target.lower().startswith(("ext::", "file:")):
        raise GitCommandError(f"remote transport is not permitted: {target!r}")
    if target.startswith(("\\\\", "//")):
        raise GitCommandError("UNC and device remote paths are not permitted")
    if Path(target).is_absolute():
        if allow_local_path:
            return target, True
        raise GitCommandError("named remotes must not resolve to local filesystem paths")
    parsed = urlsplit(target)
    if parsed.scheme in {"https", "ssh", "git"} and parsed.hostname:
        if (parsed.username and parsed.username.startswith("-")) or parsed.hostname.startswith("-"):
            raise GitCommandError(f"remote URL user and host must not start with '-': {target!r}")
        return target, False
    if _SCP_REMOTE_RE.fullmatch(target):
        user_host, _ = target.split(":", 1)
        user, host = user_host.split("@", 1)
        if user.startswith("-") or host.startswith("-"):
            raise GitCommandError(f"remote SCP user and host must not start with '-': {target!r}")
        return target, False
    raise GitCommandError(f"remote must be a safe HTTPS, SSH, Git, or explicit local path: {target!r}")


def _remote_target(repo: str | os.PathLike[str], remote: str) -> tuple[str, bool]:
    if not remote:
        raise GitCommandError("remote must not be blank")
    if _REMOTE_NAME_RE.fullmatch(remote):
        configured = _git(repo, "config", "--local", "--get", f"remote.{remote}.url")
        return _validate_remote_target(configured, allow_local_path=False)
    return _validate_remote_target(remote, allow_local_path=True)


def _remote_sha(repo: str | os.PathLike[str], remote: str, branch: str) -> str:
    target, allow_local_file_transport = _remote_target(repo, remote)
    ref = f"refs/heads/{_integration_name(branch)}"
    output = _git(
        repo,
        "ls-remote",
        "--exit-code",
        target,
        ref,
        allow_local_file_transport=allow_local_file_transport,
        isolated_repository=True,
    )
    rows = [line.split() for line in output.splitlines() if line.strip()]
    if len(rows) != 1 or len(rows[0]) != 2 or rows[0][1] != ref or not _SHA_RE.fullmatch(rows[0][0]):
        raise GitCommandError(f"remote {target!r} returned malformed or ambiguous result for {ref!r}")
    return rows[0][0]


@dataclass(frozen=True)
class ExpectedState:
    schema_version: str
    repository_id: str
    worktree: str
    branch: str
    default_branch: str
    local_default_sha: str
    feature_tip: str
    clean: bool
    remote: str
    remote_ref: str
    remote_sha: str
    lease_path: str
    lease_digest: str
    lease_owner: str
    captured_at: str

    def to_mapping(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "ExpectedState":
        required = {field.name for field in cls.__dataclass_fields__.values()}
        if set(value) != required:
            raise WorkspaceError(
                f"invalid expected-state fields: expected {sorted(required)!r}, observed {sorted(value)!r}"
            )
        try:
            state = cls(**value)  # type: ignore[arg-type]
        except TypeError as exc:
            raise WorkspaceError("invalid expected-state field types") from exc
        string_fields = required - {"clean"}
        if any(not isinstance(getattr(state, name), str) for name in string_fields):
            raise WorkspaceError("expected-state string field has an invalid type")
        if not isinstance(state.clean, bool):
            raise WorkspaceError("expected-state clean field must be boolean")
        if state.schema_version != STATE_SCHEMA_VERSION:
            raise WorkspaceError(f"unsupported expected-state schema: {state.schema_version!r}")
        if not re.fullmatch(r"[0-9a-f]{64}", state.repository_id):
            raise WorkspaceError("expected-state repository_id is malformed")
        for name in ("local_default_sha", "feature_tip", "remote_sha"):
            if not _SHA_RE.fullmatch(getattr(state, name)):
                raise WorkspaceError(f"expected-state {name} is malformed")
        if state.remote_ref != f"refs/heads/{_integration_name(state.default_branch)}":
            raise WorkspaceError("expected-state remote_ref does not match default_branch")
        lease_values = (state.lease_path, state.lease_digest, state.lease_owner)
        if any(lease_values) and not all(lease_values):
            raise WorkspaceError("expected-state lease fields must be all present or all empty")
        if state.lease_digest and not re.fullmatch(r"[0-9a-f]{64}", state.lease_digest):
            raise WorkspaceError("expected-state lease_digest is malformed")
        _parse_utc(state.captured_at)
        return state


def capture_expected_state(
    repo: str | os.PathLike[str],
    default_branch: str,
    *,
    remote: str = "origin",
    lease: LeaseHandle | None = None,
    require_clean: bool = True,
    now: datetime | None = None,
) -> ExpectedState:
    """Capture completion state using a live remote read, never a remote-tracking ref."""

    current = _ensure_utc(now or _utc_now())
    worktree = _worktree_root(repo)
    common_dir = resolve_common_dir(repo)
    branch = _current_branch(repo)
    default = _integration_name(default_branch)
    clean = _is_clean(repo)
    if require_clean and not clean:
        raise StateDriftError(("worktree is not clean",))

    lease_path = lease_digest = lease_owner = ""
    if lease is not None:
        observed, _, observed_digest = _read_lease(lease.path)
        differences: list[str] = []
        if observed_digest != lease.digest:
            differences.append("lease digest changed")
        if observed.owner != lease.record.owner:
            differences.append("lease owner changed")
        if observed.repository_id != _repository_id(common_dir):
            differences.append("lease repository identity differs")
        if observed.worktree != _normalized_path(worktree):
            differences.append("lease worktree differs")
        if observed.branch != branch:
            differences.append("lease branch differs")
        if observed.integration_branch != default:
            differences.append("lease integration branch differs")
        if _parse_utc(observed.expires_at) <= current:
            differences.append("lease is expired and requires human_gate")
        if differences:
            raise StateDriftError(differences)
        lease_path = _normalized_path(lease.path)
        lease_digest = observed_digest
        lease_owner = observed.owner

    return ExpectedState(
        schema_version=STATE_SCHEMA_VERSION,
        repository_id=_repository_id(common_dir),
        worktree=_normalized_path(worktree),
        branch=branch,
        default_branch=default,
        local_default_sha=_head(repo, default),
        feature_tip=_head(repo),
        clean=clean,
        remote=remote,
        remote_ref=f"refs/heads/{default}",
        remote_sha=_remote_sha(repo, remote, default),
        lease_path=lease_path,
        lease_digest=lease_digest,
        lease_owner=lease_owner,
        captured_at=_utc_text(current),
    )


def verify_expected_state(
    expected: ExpectedState,
    repo: str | os.PathLike[str],
    *,
    now: datetime | None = None,
) -> ExpectedState:
    """Re-read all completion inputs and raise StateDriftError on any mismatch."""

    lease = None
    if expected.lease_path:
        record, _, digest = _read_lease(Path(expected.lease_path))
        lease = LeaseHandle(Path(expected.lease_path), digest, record)
    observed = capture_expected_state(
        repo,
        expected.default_branch,
        remote=expected.remote,
        lease=lease,
        require_clean=expected.clean,
        now=now,
    )
    fields = (
        "repository_id",
        "worktree",
        "branch",
        "default_branch",
        "local_default_sha",
        "feature_tip",
        "clean",
        "remote",
        "remote_ref",
        "remote_sha",
        "lease_path",
        "lease_digest",
        "lease_owner",
    )
    differences = [
        f"{name}: expected {getattr(expected, name)!r}, observed {getattr(observed, name)!r}"
        for name in fields
        if getattr(expected, name) != getattr(observed, name)
    ]
    if differences:
        raise StateDriftError(differences)
    return observed


@dataclass(frozen=True)
class AuditBaseline:
    repository_id: str
    worktree: str
    branch: str
    head: str
    started_at: str

    def to_mapping(self) -> dict[str, object]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, value: Mapping[str, object]) -> "AuditBaseline":
        required = {field.name for field in cls.__dataclass_fields__.values()}
        if set(value) != required or any(not isinstance(value[name], str) for name in required):
            raise WorkspaceError("invalid audit-baseline record")
        baseline = cls(**value)  # type: ignore[arg-type]
        if not re.fullmatch(r"[0-9a-f]{64}", baseline.repository_id):
            raise WorkspaceError("audit-baseline repository_id is malformed")
        if not _SHA_RE.fullmatch(baseline.head):
            raise WorkspaceError("audit-baseline head is malformed")
        _parse_utc(baseline.started_at)
        return baseline


@dataclass(frozen=True)
class AuditResult:
    stable: bool
    start: AuditBaseline
    end_branch: str
    end_head: str
    ended_at: str
    differences: tuple[str, ...]

    def to_mapping(self) -> dict[str, object]:
        value = asdict(self)
        value["differences"] = list(self.differences)
        return value


def begin_audit(repo: str | os.PathLike[str], *, now: datetime | None = None) -> AuditBaseline:
    common_dir = resolve_common_dir(repo)
    return AuditBaseline(
        repository_id=_repository_id(common_dir),
        worktree=_normalized_path(_worktree_root(repo)),
        branch=_current_branch(repo),
        head=_head(repo),
        started_at=_utc_text(_ensure_utc(now or _utc_now())),
    )


def finish_audit(
    start: AuditBaseline,
    repo: str | os.PathLike[str],
    *,
    now: datetime | None = None,
) -> AuditResult:
    common_dir = resolve_common_dir(repo)
    end_worktree = _normalized_path(_worktree_root(repo))
    end_branch = _current_branch(repo)
    end_head = _head(repo)
    differences: list[str] = []
    if start.repository_id != _repository_id(common_dir):
        differences.append("repository identity changed")
    if start.worktree != end_worktree:
        differences.append("worktree changed")
    if start.branch != end_branch:
        differences.append(f"branch changed from {start.branch!r} to {end_branch!r}")
    if start.head != end_head:
        differences.append(f"HEAD changed from {start.head} to {end_head}")
    return AuditResult(
        stable=not differences,
        start=start,
        end_branch=end_branch,
        end_head=end_head,
        ended_at=_utc_text(_ensure_utc(now or _utc_now())),
        differences=tuple(differences),
    )
