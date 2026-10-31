"""Run-scoped immutable review identity, result, and atomic final-marker state."""
from __future__ import annotations

import hashlib
import json
import os
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Mapping, Sequence

from runtime.role_runner.schema import (
    ContractValidationError,
    SchemaProfileError,
    SchemaRegistry,
    validate_instance,
)

from .workspace import _atomic_replace, _canonical_bytes, _digest, _fsync_directory


IDENTITY_SCHEMA_ID = "urn:ai-company:contract:invocation-identity:1.0"
RESULT_SCHEMA_ID = "urn:ai-company:contract:review-result:1.0"
MARKER_SCHEMA_IDS = {
    "1.0.0": "urn:ai-company:contract:review-final-marker:1.0",
    "2.0.0": "urn:ai-company:contract:review-final-marker:2.0",
}
REVIEW_ROLES = frozenset({"reviewer", "qe-verify", "security"})
FINALIZER_ROLES = frozenset({"orchestrator", "adjudicator", "chairman"})
OK_VERDICTS = frozenset({"CLEAN", "ACCEPT"})


class ReviewStateError(RuntimeError):
    """Review state is malformed, conflicting, or not owned by the requested invocation."""

    category = "state_conflict"


@dataclass(frozen=True)
class SourceBinding:
    repository_id: str
    branch: str
    base_sha: str
    reviewed_tip_sha: str
    policy_version: str


@dataclass(frozen=True)
class PanelSelection:
    """Deterministic review-panel selection and explicit diversity degradation evidence."""

    invocation_ids: tuple[str, ...]
    providers: tuple[str, ...]
    diversity_status: str


def select_review_panel(
    candidates: Sequence[Mapping[str, object]],
    *,
    author_invocation_id: str,
    required_count: int = 2,
    allowed_providers: Sequence[str] | None = None,
) -> PanelSelection:
    """Apply actor eligibility first, then prefer provider heterogeneity when it exists."""

    if required_count < 1:
        raise ReviewStateError("required review count must be positive")
    author_id = _uuid_text(author_invocation_id, "author_invocation_id")
    allowed = set(allowed_providers) if allowed_providers is not None else None
    eligible: dict[str, Mapping[str, object]] = {}
    for candidate in candidates:
        try:
            invocation_id = _uuid_text(candidate["invocation_id"], "candidate invocation_id")
            provider = str(candidate["provider"])
            role = str(candidate["role"])
        except KeyError as exc:
            raise ReviewStateError(f"panel candidate is missing {exc.args[0]}") from exc
        if invocation_id == author_id or role not in REVIEW_ROLES:
            continue
        if not provider or (allowed is not None and provider not in allowed):
            continue
        if invocation_id in eligible:
            raise ReviewStateError("panel candidates contain a duplicate invocation")
        eligible[invocation_id] = candidate
    ordered = sorted(
        eligible.values(),
        key=lambda item: (str(item["provider"]), str(item["invocation_id"])),
    )
    if len(ordered) < required_count:
        raise ReviewStateError("too few eligible distinct reviewer invocations")

    selected: list[Mapping[str, object]] = []
    provider_heads: dict[str, Mapping[str, object]] = {}
    for candidate in ordered:
        provider_heads.setdefault(str(candidate["provider"]), candidate)
    for provider in sorted(provider_heads):
        if len(selected) == required_count:
            break
        selected.append(provider_heads[provider])
    if len(selected) < required_count:
        selected_ids = {str(candidate["invocation_id"]) for candidate in selected}
        selected.extend(
            candidate
            for candidate in ordered
            if str(candidate["invocation_id"]) not in selected_ids
        )
        selected = selected[:required_count]
    providers = tuple(str(candidate["provider"]) for candidate in selected)
    return PanelSelection(
        invocation_ids=tuple(str(candidate["invocation_id"]) for candidate in selected),
        providers=providers,
        diversity_status=(
            "heterogeneous" if len(set(providers)) > 1 else "single-provider-degraded"
        ),
    )


def _uuid_text(value: object, label: str) -> str:
    try:
        return str(uuid.UUID(str(value)))
    except (ValueError, AttributeError) as exc:
        raise ReviewStateError(f"{label} must be a canonical UUID") from exc


def _read_object(path: Path, label: str) -> dict[str, object]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ReviewStateError(f"{label} is missing or unreadable: {exc}") from exc
    if not isinstance(value, dict):
        raise ReviewStateError(f"{label} must contain a JSON object")
    return value


def _marker_schema_id(marker: Mapping[str, object]) -> str:
    schema_version = marker.get("schema_version")
    if not isinstance(schema_version, str) or schema_version not in MARKER_SCHEMA_IDS:
        raise ReviewStateError("final marker has an unsupported schema_version")
    return MARKER_SCHEMA_IDS[schema_version]


def _create_immutable(path: Path, data: bytes) -> None:
    """Publish complete bytes through a create-only hard link; readers never observe partial data."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4()}.tmp")
    try:
        with temporary.open("xb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as exc:
            raise ReviewStateError(f"immutable record already exists: {path}") from exc
        _fsync_directory(path.parent)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


class ReviewStateStore:
    """Validated filesystem state for parallel reviewers and one CAS finalizer."""

    def __init__(self, root: str | Path, contract_directory: str | Path):
        self.root = Path(root).resolve()
        self.root.mkdir(parents=True, exist_ok=True)
        try:
            self.registry = SchemaRegistry.from_directory(contract_directory)
        except SchemaProfileError as exc:
            raise ReviewStateError(f"contract registry cannot be loaded: {exc}") from exc

    def _invocation_directory(self, run_id: object, invocation_id: object) -> Path:
        run = _uuid_text(run_id, "run_id")
        invocation = _uuid_text(invocation_id, "invocation_id")
        return self.root / run / "invocations" / invocation

    def identity_path(self, run_id: object, invocation_id: object) -> Path:
        return self._invocation_directory(run_id, invocation_id) / "identity.json"

    def result_path(self, run_id: object, reviewer_invocation_id: object) -> Path:
        return self._invocation_directory(run_id, reviewer_invocation_id) / "review-result.json"

    def marker_path(self, run_id: object) -> Path:
        return self.root / _uuid_text(run_id, "run_id") / "final" / "review-verdict.json"

    def issue_identity(self, identity: Mapping[str, object]) -> Path:
        self._validate(identity, IDENTITY_SCHEMA_ID, "invocation identity")
        path = self.identity_path(identity["run_id"], identity["invocation_id"])
        _create_immutable(path, _canonical_bytes(identity))
        return path

    def read_identity(self, run_id: object, invocation_id: object) -> dict[str, object]:
        value = _read_object(self.identity_path(run_id, invocation_id), "invocation identity")
        self._validate(value, IDENTITY_SCHEMA_ID, "invocation identity")
        if value["run_id"] != _uuid_text(run_id, "run_id"):
            raise ReviewStateError("identity run_id does not match its path")
        if value["invocation_id"] != _uuid_text(invocation_id, "invocation_id"):
            raise ReviewStateError("identity invocation_id does not match its path")
        return value

    def write_result(self, result: Mapping[str, object]) -> Path:
        self._validate(result, RESULT_SCHEMA_ID, "review result")
        run_id = result["run_id"]
        author_id = result["author_invocation_id"]
        reviewer_id = result["reviewer_invocation_id"]
        author = self.read_identity(run_id, author_id)
        reviewer = self.read_identity(run_id, reviewer_id)
        if author_id == reviewer_id:
            raise ReviewStateError("an invocation cannot review its own output")
        if reviewer["role"] not in REVIEW_ROLES:
            raise ReviewStateError(f"invocation role {reviewer['role']!r} is not a review role")
        if author["role"] in REVIEW_ROLES:
            raise ReviewStateError("review result author must identify a producing invocation")
        path = self.result_path(run_id, reviewer_id)
        _create_immutable(path, _canonical_bytes(result))
        return path

    def read_result(self, run_id: object, reviewer_invocation_id: object) -> dict[str, object]:
        value = _read_object(self.result_path(run_id, reviewer_invocation_id), "review result")
        self._validate(value, RESULT_SCHEMA_ID, "review result")
        if value["run_id"] != _uuid_text(run_id, "run_id"):
            raise ReviewStateError("review result run_id does not match its path")
        if value["reviewer_invocation_id"] != _uuid_text(
            reviewer_invocation_id, "reviewer_invocation_id"
        ):
            raise ReviewStateError("reviewer invocation does not match result path")
        return value

    def finalize(
        self,
        *,
        run_id: str,
        author_invocation_id: str,
        reviewer_invocation_ids: Sequence[str],
        finalized_by: str,
        source: SourceBinding,
        finalized_at: str,
        expected_prior_digest: str | None,
        replace_fn: Callable[[str, str], object] = os.replace,
    ) -> dict[str, object]:
        run = _uuid_text(run_id, "run_id")
        author_id = _uuid_text(author_invocation_id, "author_invocation_id")
        # The label carries the REAL requirement. "must be a canonical UUID" alone sent a
        # caller who read it literally back with another valid UUID that failed the same
        # way, because the true condition is membership in this run with a finalizer role
        # -- discoverable only by reading the check below. (backlog P1-15)
        finalizer_id = _uuid_text(
            finalized_by,
            "finalized_by (an invocation identity issued in THIS run whose role is one of "
            + "/".join(sorted(FINALIZER_ROLES)) + ")",
        )
        reviewer_ids = tuple(_uuid_text(item, "reviewer_invocation_id") for item in reviewer_invocation_ids)
        if not reviewer_ids or len(set(reviewer_ids)) != len(reviewer_ids):
            raise ReviewStateError("reviewer invocation IDs must be non-empty and unique")
        if author_id in reviewer_ids:
            raise ReviewStateError("an invocation cannot review its own output")

        author = self.read_identity(run, author_id)
        finalizer = self.read_identity(run, finalizer_id)
        if finalizer["role"] not in FINALIZER_ROLES:
            # Derived, like the `finalized_by` label above. This message had ALREADY drifted --
            # it named orchestrator/adjudicator while FINALIZER_ROLES also contains
            # chairman -- in the same function whose sibling message was being fixed for
            # exactly that reason. Found by a cold reviewer, not by the pass that wrote the
            # fix three lines away. Restating a set beside the set is how both drifted.
            raise ReviewStateError(
                "final marker may only be written by "
                + "/".join(sorted(FINALIZER_ROLES))
            )
        if author["role"] in REVIEW_ROLES:
            raise ReviewStateError("author invocation is not a producing role")

        results = [self.read_result(run, reviewer_id) for reviewer_id in reviewer_ids]
        reviewers = [self.read_identity(run, reviewer_id) for reviewer_id in reviewer_ids]
        expected_source = {
            "repository_id": source.repository_id,
            "branch": source.branch,
            "base_sha": source.base_sha,
            "reviewed_tip_sha": source.reviewed_tip_sha,
            "policy_version": source.policy_version,
            "author_invocation_id": author_id,
        }
        for result, reviewer_id, reviewer in zip(results, reviewer_ids, reviewers):
            for field, expected in expected_source.items():
                if result[field] != expected:
                    raise ReviewStateError(f"review result {reviewer_id} has mismatched {field}")
            if result["reviewer_invocation_id"] != reviewer_id:
                raise ReviewStateError("review result is attributed to the wrong reviewer")
            if reviewer["role"] not in REVIEW_ROLES:
                raise ReviewStateError("review result identity is no longer eligible")

        production_entries = results[0]["production_entries"]
        if any(result["production_entries"] != production_entries for result in results[1:]):
            raise ReviewStateError("review results do not bind the same production entries")
        result_digests = [
            hashlib.sha256(self.result_path(run, reviewer_id).read_bytes()).hexdigest()
            for reviewer_id in reviewer_ids
        ]
        author_identity_digest = hashlib.sha256(
            self.identity_path(run, author_id).read_bytes()
        ).hexdigest()
        reviewer_identity_digests = [
            hashlib.sha256(self.identity_path(run, reviewer_id).read_bytes()).hexdigest()
            for reviewer_id in reviewer_ids
        ]
        finalizer_identity_digest = hashlib.sha256(
            self.identity_path(run, finalizer_id).read_bytes()
        ).hexdigest()
        verdict = "CLEAN" if all(result["verdict"] in OK_VERDICTS for result in results) else "REJECT"
        marker: dict[str, object] = {
            "schema_version": "2.0.0",
            "repository_id": source.repository_id,
            "branch": source.branch,
            "base_sha": source.base_sha,
            "reviewed_tip_sha": source.reviewed_tip_sha,
            "run_id": run,
            "author_invocation_id": author_id,
            "reviewers": [
                {
                    "invocation_id": reviewer_id,
                    "provider": reviewer["provider"],
                    "model": reviewer["model"],
                    "identity_digest": identity_digest,
                    "result_digest": result_digest,
                }
                for reviewer_id, reviewer, identity_digest, result_digest in zip(
                    reviewer_ids, reviewers, reviewer_identity_digests, result_digests
                )
            ],
            "author_identity_digest": author_identity_digest,
            "finalizer_identity_digest": finalizer_identity_digest,
            "policy_version": source.policy_version,
            "verdict": verdict,
            "production_entries": production_entries,
            "diversity_status": (
                "heterogeneous"
                if len({str(reviewer["provider"]) for reviewer in reviewers}) > 1
                else "single-provider-degraded"
            ),
            "finalized_by": finalizer_id,
            "finalized_at": finalized_at,
            "previous_marker_digest": expected_prior_digest,
        }
        self._validate(marker, MARKER_SCHEMA_IDS["2.0.0"], "final marker")

        path = self.marker_path(run)
        path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = path.parent / "finalizer.lock"
        try:
            with lock_path.open("x", encoding="ascii") as lock:
                lock.write(finalizer_id)
                lock.flush()
                os.fsync(lock.fileno())
        except FileExistsError as exc:
            raise ReviewStateError("another finalizer owns this run") from exc
        try:
            observed_prior = _digest(path.read_bytes()) if path.is_file() else None
            if observed_prior != expected_prior_digest:
                raise ReviewStateError(
                    f"final marker CAS mismatch: expected {expected_prior_digest}, observed {observed_prior}"
                )
            _atomic_replace(path, _canonical_bytes(marker), replace_fn=replace_fn)
        finally:
            try:
                lock_path.unlink()
                _fsync_directory(lock_path.parent)
            except FileNotFoundError:
                pass
        return marker

    def verify_marker(self, run_id: str, source: SourceBinding) -> dict[str, object]:
        run = _uuid_text(run_id, "run_id")
        marker = _read_object(self.marker_path(run), "final marker")
        schema_id = _marker_schema_id(marker)
        self._validate(marker, schema_id, "final marker")
        expected = {
            "run_id": run,
            "repository_id": source.repository_id,
            "branch": source.branch,
            "base_sha": source.base_sha,
            "reviewed_tip_sha": source.reviewed_tip_sha,
            "policy_version": source.policy_version,
        }
        for field, value in expected.items():
            if marker[field] != value:
                raise ReviewStateError(f"final marker has mismatched {field}")
        author_id = str(marker["author_invocation_id"])
        marker_version = str(marker["schema_version"])
        if marker_version == "1.0.0":
            reviewer_entries = [
                {
                    "invocation_id": reviewer_id,
                    "identity_digest": identity_digest,
                    "result_digest": result_digest,
                }
                for reviewer_id, identity_digest, result_digest in zip(
                    marker["reviewer_invocation_ids"],
                    marker["reviewer_identity_digests"],
                    marker["result_digests"],
                )
            ]
            if (
                len(marker["reviewer_invocation_ids"]) != len(marker["result_digests"])
                or len(marker["reviewer_invocation_ids"])
                != len(marker["reviewer_identity_digests"])
            ):
                raise ReviewStateError("final marker reviewer and digest counts differ")
        else:
            reviewer_entries = marker["reviewers"]
            if not isinstance(reviewer_entries, list):
                raise ReviewStateError("final marker reviewers must be an array")
            reviewer_ids = [str(entry["invocation_id"]) for entry in reviewer_entries]
            if len(set(reviewer_ids)) != len(reviewer_ids):
                raise ReviewStateError("final marker reviewers are not unique")
            providers = []
            for entry in reviewer_entries:
                if not isinstance(entry, dict):
                    raise ReviewStateError("final marker reviewer entry is malformed")
                providers.append(str(entry["provider"]))
            expected_diversity = (
                "heterogeneous" if len(set(providers)) > 1 else "single-provider-degraded"
            )
            if marker["diversity_status"] != expected_diversity:
                raise ReviewStateError("final marker diversity_status does not match reviewers")
        reviewer_ids = [str(entry["invocation_id"]) for entry in reviewer_entries]
        if author_id in reviewer_ids:
            raise ReviewStateError("final marker contains a self-review invocation")
        author = self.read_identity(run, author_id)
        observed_author_digest = hashlib.sha256(
            self.identity_path(run, author_id).read_bytes()
        ).hexdigest()
        if observed_author_digest != marker["author_identity_digest"]:
            raise ReviewStateError("final marker author identity digest mismatch")
        if author["role"] in REVIEW_ROLES:
            raise ReviewStateError("final marker author is not a producing invocation")
        finalizer_id = str(marker["finalized_by"])
        for entry in reviewer_entries:
            reviewer_id = str(entry["invocation_id"])
            expected_digest = str(entry["result_digest"])
            expected_identity_digest = str(entry["identity_digest"])
            reviewer = self.read_identity(run, reviewer_id)
            observed_identity_digest = hashlib.sha256(
                self.identity_path(run, reviewer_id).read_bytes()
            ).hexdigest()
            if observed_identity_digest != expected_identity_digest:
                raise ReviewStateError("final marker reviewer identity digest mismatch")
            if marker_version == "2.0.0" and (
                entry["provider"] != reviewer["provider"] or entry["model"] != reviewer["model"]
            ):
                raise ReviewStateError("final marker reviewer provider/model mismatch")
            if reviewer["role"] not in REVIEW_ROLES:
                raise ReviewStateError("final marker contains an ineligible reviewer invocation")
            result = self.read_result(run, reviewer_id)
            if result["author_invocation_id"] != author_id:
                raise ReviewStateError("final marker result has a different author")
            for field, expected_value in expected.items():
                if field != "run_id" and result[field] != expected_value:
                    raise ReviewStateError(f"final marker result has mismatched {field}")
            if result["production_entries"] != marker["production_entries"]:
                raise ReviewStateError("final marker production entries differ from a review result")
            observed = hashlib.sha256(self.result_path(run, reviewer_id).read_bytes()).hexdigest()
            if observed != expected_digest:
                raise ReviewStateError("final marker result digest mismatch")
            if reviewer_id == finalizer_id:
                raise ReviewStateError("final marker finalizer cannot be a reviewer")
        results_accept = all(
            self.read_result(run, reviewer_id)["verdict"] in OK_VERDICTS
            for reviewer_id in reviewer_ids
        )
        marker_accepts = marker["verdict"] in OK_VERDICTS
        if marker_accepts != results_accept:
            raise ReviewStateError("final marker verdict acceptance does not match reviewer results")
        finalizer = self.read_identity(run, finalizer_id)
        observed_finalizer_digest = hashlib.sha256(
            self.identity_path(run, finalizer_id).read_bytes()
        ).hexdigest()
        if observed_finalizer_digest != marker["finalizer_identity_digest"]:
            raise ReviewStateError("final marker finalizer identity digest mismatch")
        if finalizer["role"] not in FINALIZER_ROLES:
            raise ReviewStateError("final marker contains an ineligible finalizer invocation")
        return marker

    def _validate(self, value: Mapping[str, object], schema_id: str, label: str) -> None:
        try:
            validate_instance(value, self.registry.get(schema_id), registry=self.registry)
        except (SchemaProfileError, ContractValidationError) as exc:
            raise ReviewStateError(f"{label} is invalid: {exc}") from exc
