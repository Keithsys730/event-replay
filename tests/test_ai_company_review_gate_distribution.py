"""Portable conformance tests installed with the ai-company review-gate distribution."""
from __future__ import annotations

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "config" / "review_gate_distribution.json"
LEGACY_TEST_SHA256 = "6b05a61450684d2e891f23fb9bbaad91e1ecfe0657ff21315d660ab9e488b348"


def _manifest() -> dict[str, object]:
    value = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    assert isinstance(value, dict)
    return value


def test_distribution_manifest_and_migration_contract():
    manifest = _manifest()
    assert manifest["schema_version"] == "1.1.0"
    assert manifest["package_id"] == "ai-company-review-gate"
    assert manifest["package_version"] == "1.4.0"
    files = manifest["install_files"]
    assert isinstance(files, list)
    assert len(files) == len(set(files))
    assert "tests/test_ai_company_review_gate_distribution.py" in files
    assert all((ROOT / relative).is_file() for relative in files)
    assert manifest["migrations"] == [
        {
            "path": "tests/test_review_gate.py",
            "action": "remove_if_sha256",
            "allowed_sha256": [LEGACY_TEST_SHA256],
            "when_missing": "allow",
        }
    ]


def test_distribution_runtime_and_contracts_load_without_optimization():
    assert sys.implementation.name == "cpython"
    assert sys.version_info[:2] >= (3, 11)
    assert sys.flags.optimize == 0
    path = ROOT / "scripts" / "review_gate.py"
    spec = importlib.util.spec_from_file_location("portable_review_gate_probe", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module._V1_IMPORT_ERROR is None
    assert module.DEFAULT_MIGRATION_VERSION == "v1"
    assert module._SECURITY_PATHS_OK is True

    from runtime.role_runner.schema import SchemaRegistry

    registry = SchemaRegistry.from_directory(ROOT / "state" / "contracts")
    for schema_id in (
        "urn:ai-company:contract:invocation-identity:1.0",
        "urn:ai-company:contract:review-final-marker:1.0",
        "urn:ai-company:contract:review-result:1.0",
        "urn:ai-company:contract:security-review-attestation:1.0",
    ):
        registry.get(schema_id)


def test_distribution_contains_managed_hooks_and_common_directory_installer():
    for name in ("pre-commit", "pre-merge-commit", "post-merge", "post-commit"):
        managed = ROOT / "hooks" / name
        assert managed.read_text(encoding="utf-8").splitlines()[0] == "#!/bin/sh"
    post_merge = (ROOT / "hooks" / "post-merge").read_text(encoding="utf-8")
    assert "refs/remotes/origin/HEAD" in post_merge
    assert "ai-company.pythonExecutable" in post_merge
    assert "scripts/install_hooks.py" in post_merge
    assert "trusted-bundle-refresh" in post_merge
    post_commit = (ROOT / "hooks" / "post-commit").read_text(encoding="utf-8")
    assert "AI_COMPANY_GIT_BIN" in post_commit
    assert "--git-path hooks" in post_commit
    assert "post-merge hook is missing or not executable" in post_commit
    assert "status --porcelain --untracked-files=all" in post_commit
    assert "refresh deferred until the default-branch worktree is clean" in post_commit
    assert "--first-parent" in post_commit
    assert "--first-parent" in post_merge
    assert "--no-renames" in post_commit
    assert "--no-renames" in post_merge
    installer = (ROOT / "scripts" / "install_hooks.py").read_text(encoding="utf-8")
    installer_spec = importlib.util.spec_from_file_location(
        "post_commit_trusted_bundle_installer", ROOT / "scripts" / "install_hooks.py"
    )
    assert installer_spec is not None and installer_spec.loader is not None
    installer_module = importlib.util.module_from_spec(installer_spec)
    installer_spec.loader.exec_module(installer_module)
    refresh_sources = (
        *installer_module.TRUSTED_BUNDLE_FILES,
        *(f"hooks/{name}" for name in ("pre-commit", "pre-merge-commit", "post-merge", "post-commit")),
    )
    for source in (post_commit, post_merge):
        for relative in refresh_sources:
            assert relative in source, f"refresh dirty-tree classifier omits {relative}"
    assert "Cannot install; managed hook source is missing" in installer
    assert '"post-merge"' in installer
    assert '"--git-path", "hooks"' in installer
    assert '"--path-format=absolute"' in installer
    assert '"--python-executable"' in installer
    assert '"ai-company.pythonExecutableBlob"' in installer
    assert '"hash-object"' in installer
    assert "os.replace(temporary, target)" in installer
    assert "trustedReviewGatePath" in installer
    assert "trustedReviewGateDigest" in installer
    assert installer.index("preflight_python_runtime(python_executable, ROOT)") < installer.index(
        "for name in GIT_HOOK_NAMES:"
    )
    for name in ("pre-commit", "pre-merge-commit"):
        hook = (ROOT / "hooks" / name).read_text(encoding="utf-8")
        assert 'AI_COMPANY_GIT_BIN' in hook and 'command -v git' in hook
        assert '"$GIT_BIN" rev-parse --show-toplevel' in hook
        assert 'rev-parse --path-format=absolute --git-common-dir' in hook
        assert 'ai-company-runtime/t/${TRUSTED_DIGEST%${TRUSTED_DIGEST#????????????????}}/scripts/trusted_gate_launcher.ps1' in hook
        assert 'powershell.exe' in hook
        assert 'ai-company.pythonExecutable' not in hook
        assert "unset GIT_WORK_TREE" in hook
        # ORD-0031 / P0-22 (B4/B9): GIT_DIR appended to the SAME unset line in the distributed
        # copy too, RED until RD's fix lands. GIT_INDEX_FILE must never be unset (B3 measured:
        # tests/test_review_gate_v1.py::test_git_commit_only_partial_index_goes_blind_if_git_index_file_is_stripped
        # -- B3-OUTCOME is git-dir-only), so this holds both before and after the fix.
        assert "unset GIT_WORK_TREE GIT_DIR" in hook
        assert "GIT_INDEX_FILE" not in hook
        assert "ai-company.trustedReviewGateDigest" in hook
        assert 'trusted-bundle-check' not in hook


def test_security_attestation_procedure_uses_bound_python_and_trusted_git():
    # MED (round 3 cross-model review, same class as the trusted-bundle-file-list test below):
    # this test file is distributed, but docs/CROSS_MODEL_REVIEW_HARNESS.md is not -- confirmed by
    # execution against a consumer staged from install_files only. Skip rather than fail there.
    procedure_path = ROOT / "docs" / "CROSS_MODEL_REVIEW_HARNESS.md"
    if not procedure_path.is_file():
        pytest.skip("docs/CROSS_MODEL_REVIEW_HARNESS.md is not part of the distributed package")
    procedure = procedure_path.read_text(encoding="utf-8")
    assert '$GitExe = if ($env:AI_COMPANY_GIT_BIN' in procedure
    assert "$TrustedGateDigest = & $GitExe config --local --get ai-company.trustedReviewGateDigest" in procedure
    assert "$CommonGitDir = & $GitExe rev-parse --path-format=absolute --git-common-dir" in procedure
    assert "trusted_gate_launcher.ps1" in procedure
    assert "-TargetRoot $CandidateRoot -Command attestation-template" in procedure
    assert "-TargetRoot $CandidateRoot -Command attestation-check" in procedure
    assert "Security attestation template creation failed." in procedure
    assert '$SshKeygenExe = "$env:SystemRoot/System32/OpenSSH/ssh-keygen.exe"' in procedure


def _extract_powershell_string_array(text: str, variable_name: str) -> tuple[str, ...]:
    match = re.search(
        r"\$script:" + re.escape(variable_name) + r"\s*=\s*@\((.*?)\n[ \t]*\)",
        text,
        re.DOTALL,
    )
    assert match is not None, f"could not locate ${{script:{variable_name}}} = @(...) block"
    return tuple(re.findall(r"'([^']+)'", match.group(1)))


def test_trusted_bundle_file_list_matches_across_all_four_hand_maintained_copies():
    # LOW (round 1 cross-model review): scripts/review_gate.py, scripts/install_hooks.py,
    # scripts/verify-hook-integrity.ps1, and tests/VerifyHookIntegrity.Tests.ps1 each maintain
    # their own copy of the trusted-bundle file list. A divergence fails loud (it changes the
    # SHA-256, so check 6 / trusted-bundle-check report DRIFT rather than silently skipping a
    # file) but produces a permanently unfixable DRIFT state an operator can only resolve by
    # ignoring the check -- alert fatigue on the sole detective control over the trust root.
    # This asserts all four copies stay identical (order included) so a future edit to any one of
    # them is caught here instead of surfacing as a confusing DRIFT report later.
    #
    # MED (round 3 cross-model review): this test file is itself distributed
    # (config/review_gate_distribution.json's install_files), but
    # scripts/verify-hook-integrity.ps1 and tests/VerifyHookIntegrity.Tests.ps1 are NOT --
    # confirmed by execution against a consumer staged from install_files only, which raised
    # FileNotFoundError on both reads and would have shipped a permanently-red conformance suite
    # to every downstream consumer. Skip (not assert-fail) when those two ai-company-repo-only
    # files are absent; the assertion still runs, and still catches drift, in the canonical repo.
    verify_script_path = ROOT / "scripts" / "verify-hook-integrity.ps1"
    verify_test_path = ROOT / "tests" / "VerifyHookIntegrity.Tests.ps1"
    if not verify_script_path.is_file() or not verify_test_path.is_file():
        pytest.skip("scripts/verify-hook-integrity.ps1 and its Pester test are not part of the distributed package")

    installer_path = ROOT / "scripts" / "install_hooks.py"
    installer_spec = importlib.util.spec_from_file_location("trusted_bundle_installer_list", installer_path)
    assert installer_spec is not None and installer_spec.loader is not None
    installer = importlib.util.module_from_spec(installer_spec)
    installer_spec.loader.exec_module(installer)
    canonical = installer.TRUSTED_BUNDLE_FILES

    gate_path = ROOT / "scripts" / "review_gate.py"
    gate_spec = importlib.util.spec_from_file_location("trusted_bundle_gate_list", gate_path)
    assert gate_spec is not None and gate_spec.loader is not None
    gate = importlib.util.module_from_spec(gate_spec)
    gate_spec.loader.exec_module(gate)
    assert gate._TRUSTED_BUNDLE_FILES == canonical

    verify_text = verify_script_path.read_text(encoding="utf-8")
    assert _extract_powershell_string_array(verify_text, "VerifyHookIntegrityTrustedBundleFiles") == canonical

    test_fixture_text = verify_test_path.read_text(encoding="utf-8")
    assert _extract_powershell_string_array(test_fixture_text, "TrustedBundleFiles") == canonical


def test_distribution_installs_a_hash_pinned_trusted_gate_bundle():
    installer_path = ROOT / "scripts" / "install_hooks.py"
    installer_spec = importlib.util.spec_from_file_location("trusted_bundle_installer", installer_path)
    assert installer_spec is not None and installer_spec.loader is not None
    installer = importlib.util.module_from_spec(installer_spec)
    installer_spec.loader.exec_module(installer)

    gate_path = ROOT / "scripts" / "review_gate.py"
    gate_spec = importlib.util.spec_from_file_location("trusted_bundle_gate", gate_path)
    assert gate_spec is not None and gate_spec.loader is not None
    gate = importlib.util.module_from_spec(gate_spec)
    gate_spec.loader.exec_module(gate)
    assert installer.TRUSTED_BUNDLE_FILES == gate._TRUSTED_BUNDLE_FILES

    with tempfile.TemporaryDirectory(prefix="ai-company-trusted-gate-") as temporary:
        bundle_root, digest = installer.install_trusted_bundle(ROOT, Path(temporary) / "hooks")
        assert digest == installer.trusted_bundle_digest(ROOT)
        assert (bundle_root / "scripts" / "review_gate.py").read_bytes() == gate_path.read_bytes()
        assert (bundle_root / "scripts" / "trusted_gate_launcher.ps1").is_file()
        for relative in installer.TRUSTED_BUNDLE_FILES:
            assert (bundle_root / relative).is_file()

        verified = subprocess.run(
            [
                sys.executable,
                "-B",
                str(bundle_root / "scripts" / "review_gate.py"),
                "trusted-bundle-check",
                "--expected-digest",
                digest,
            ],
            cwd=bundle_root,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
        assert verified.returncode == 0, verified.stdout + verified.stderr


def test_installer_runtime_preflight_rejects_startup_files_before_hook_install(tmp_path):
    installer_path = ROOT / "scripts" / "install_hooks.py"
    spec = importlib.util.spec_from_file_location("installer_runtime_preflight", installer_path)
    assert spec is not None and spec.loader is not None
    installer = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(installer)

    candidate = tmp_path / "candidate"
    candidate.mkdir()
    runtime = tmp_path / "runtime"
    runtime.mkdir()
    python = runtime / "python.exe"
    python.write_bytes(b"not an interpreter")
    (runtime / "python311._pth").write_text("import site\n", encoding="utf-8")

    try:
        installer.preflight_python_runtime(python, candidate)
    except ValueError as exc:
        assert "forbidden venv or ._pth startup files" in str(exc)
    else:
        raise AssertionError("installer must reject startup files before installing hooks")


def test_trusted_launcher_runs_only_the_installed_gate_and_rejects_candidate_python():
    installer_path = ROOT / "scripts" / "install_hooks.py"
    installer_spec = importlib.util.spec_from_file_location("trusted_launcher_installer", installer_path)
    assert installer_spec is not None and installer_spec.loader is not None
    installer = importlib.util.module_from_spec(installer_spec)
    installer_spec.loader.exec_module(installer)

    work = Path(tempfile.mkdtemp(prefix="ai-company-launcher-"))
    try:
        candidate = work / "candidate"
        candidate.mkdir()
        subprocess.run(["git", "-C", str(candidate), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(candidate), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(candidate), "config", "user.name", "Test"], check=True)
        (candidate / "README.md").write_text("baseline\n", encoding="utf-8")
        (candidate / ".gitignore").write_text(".devteam/\n", encoding="utf-8")
        candidate_gate = candidate / "scripts" / "review_gate.py"
        candidate_gate.parent.mkdir()
        candidate_gate.write_text("raise SystemExit('candidate gate was executed')\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(candidate), "add", "."], check=True)
        subprocess.run(["git", "-C", str(candidate), "commit", "-qm", "baseline"], check=True)
        subprocess.run(["git", "-C", str(candidate), "branch", "-M", "main"], check=True)

        common_hooks = work / "common" / "hooks"
        common_hooks.mkdir(parents=True)
        bundle_root, digest = installer.install_trusted_bundle(ROOT, common_hooks)
        _, closure_digest = installer.install_interpreter_closure_manifest(
            Path(sys.executable), bundle_root / "scripts" / "review_gate.py", bundle_root
        )
        python_blob = subprocess.run(
        ["git", "hash-object", "--no-filters", "--", sys.executable],
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
        ).stdout.strip()
        for key, value in (
        ("ai-company.pythonExecutable", sys.executable),
        ("ai-company.pythonExecutableBlob", python_blob),
        ("ai-company.trustedReviewGatePath", str(bundle_root / "scripts" / "review_gate.py")),
        ("ai-company.trustedReviewGateDigest", digest),
        ("ai-company.pythonInterpreterClosureDigest", closure_digest),
        ):
            subprocess.run(["git", "-C", str(candidate), "config", "--local", key, value], check=True)

        launcher = bundle_root / "scripts" / "trusted_gate_launcher.ps1"
        command = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(launcher),
        "-TargetRoot", str(candidate), "-Command", "identity-issue",
        "--run-id", "113e4567-e89b-12d3-a456-426614174000",
        "--invocation-id", "213e4567-e89b-12d3-a456-426614174000",
        "--role", "reviewer", "--provider", "openai", "--model", "gpt-5.6-sol",
        "--runner-instance-id", "313e4567-e89b-12d3-a456-426614174000",
        ]
        result = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert result.returncode == 0, result.stdout + result.stderr
        identity = candidate / ".devteam" / "runs" / "113e4567-e89b-12d3-a456-426614174000" / "invocations" / "213e4567-e89b-12d3-a456-426614174000" / "identity.json"
        assert identity.is_file()

        # Candidate-controlled startup files are rejected before Python can execute them.  This
        # models both ``pythonXY._pth`` + ``import site`` and a virtual-environment pyvenv.cfg.
        external_python = work / "external-python" / "python.exe"
        external_python.parent.mkdir()
        external_python.write_bytes(b"not an interpreter")
        (external_python.parent / "python311._pth").write_text("import site\n", encoding="utf-8")
        subprocess.run(
            ["git", "-C", str(candidate), "config", "--local", "ai-company.pythonExecutable", str(external_python)],
            check=True,
        )
        pth_rejected = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert pth_rejected.returncode == 1
        assert "forbidden venv or ._pth startup files" in pth_rejected.stderr

        (external_python.parent / "python311._pth").unlink()
        (external_python.parent / "pyvenv.cfg").write_text("home = C:/untrusted\n", encoding="utf-8")
        venv_rejected = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert venv_rejected.returncode == 1
        assert "forbidden venv or ._pth startup files" in venv_rejected.stderr

        candidate_python = candidate / "python.exe"
        candidate_python.write_bytes(b"not an interpreter")
        subprocess.run(
        ["git", "-C", str(candidate), "config", "--local", "ai-company.pythonExecutable", str(candidate_python)],
        check=True,
        )
        rejected = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert rejected.returncode == 1
        assert "must not be inside the candidate target root" in rejected.stderr
        assert identity.is_file()
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_trusted_launcher_accepts_sha256_git_object_ids_and_rejects_nested_target():
    installer_spec = importlib.util.spec_from_file_location(
        "trusted_launcher_sha256_installer", ROOT / "scripts" / "install_hooks.py"
    )
    assert installer_spec is not None and installer_spec.loader is not None
    installer = importlib.util.module_from_spec(installer_spec)
    installer_spec.loader.exec_module(installer)

    work = Path(tempfile.mkdtemp(prefix="ai-company-sha256-"))
    try:
        candidate = work / "candidate"
        result = subprocess.run(
        ["git", "init", "--object-format=sha256", "-q", str(candidate)],
        capture_output=True, text=True, encoding="utf-8", errors="replace",
    )
        if result.returncode != 0:
            import pytest
            pytest.skip("installed Git does not support SHA-256 repositories")
        subprocess.run(["git", "-C", str(candidate), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(candidate), "config", "user.name", "Test"], check=True)
        (candidate / "README.md").write_text("baseline\n", encoding="utf-8")
        nested = candidate / "nested"
        nested.mkdir()
        subprocess.run(["git", "-C", str(candidate), "add", "."], check=True)
        subprocess.run(["git", "-C", str(candidate), "commit", "-qm", "baseline"], check=True)

        common_hooks = work / "common" / "hooks"
        common_hooks.mkdir(parents=True)
        bundle_root, digest = installer.install_trusted_bundle(ROOT, common_hooks)
        _, closure_digest = installer.install_interpreter_closure_manifest(
            Path(sys.executable), bundle_root / "scripts" / "review_gate.py", bundle_root
        )
        python_blob = subprocess.run(
        ["git", "-C", str(candidate), "hash-object", "--no-filters", "--", sys.executable],
        check=True, capture_output=True, text=True, encoding="utf-8",
        ).stdout.strip()
        assert len(python_blob) == 64
        for key, value in (
        ("ai-company.pythonExecutable", sys.executable),
        ("ai-company.pythonExecutableBlob", python_blob),
        ("ai-company.trustedReviewGatePath", str(bundle_root / "scripts" / "review_gate.py")),
        ("ai-company.trustedReviewGateDigest", digest),
        ("ai-company.pythonInterpreterClosureDigest", closure_digest),
        ):
            subprocess.run(["git", "-C", str(candidate), "config", "--local", key, value], check=True)

        launcher = bundle_root / "scripts" / "trusted_gate_launcher.ps1"
        command = [
        "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(launcher),
        "-TargetRoot", str(candidate), "-Command", "identity-issue",
        "--run-id", "113e4567-e89b-12d3-a456-426614174001",
        "--invocation-id", "213e4567-e89b-12d3-a456-426614174001",
        "--role", "reviewer", "--provider", "openai", "--model", "gpt-5.6-sol",
        "--runner-instance-id", "313e4567-e89b-12d3-a456-426614174001",
        ]
        accepted = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert accepted.returncode == 0, accepted.stdout + accepted.stderr
        nested_command = [*command]
        nested_command[nested_command.index(str(candidate))] = str(nested)
        rejected = subprocess.run(nested_command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert rejected.returncode == 1
        assert "must equal the Git repository top-level" in rejected.stderr
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_trusted_launcher_rejects_tampered_interpreter_closure():
    """HIGH (cross-model review, round 3): the launcher must verify Lib/DLLs content against a
    pinned closure digest before pointing sys.path at it. This exercises that check directly --
    a wrong-but-well-formed digest, an invalid-format digest, a tampered manifest, and a missing
    manifest must each be rejected with their specific message, while the untampered install
    still succeeds."""
    installer_spec = importlib.util.spec_from_file_location(
        "trusted_launcher_closure_installer", ROOT / "scripts" / "install_hooks.py"
    )
    assert installer_spec is not None and installer_spec.loader is not None
    installer = importlib.util.module_from_spec(installer_spec)
    installer_spec.loader.exec_module(installer)

    work = Path(tempfile.mkdtemp(prefix="ai-company-closure-"))
    try:
        candidate = work / "candidate"
        candidate.mkdir()
        subprocess.run(["git", "-C", str(candidate), "init", "-q"], check=True)
        subprocess.run(["git", "-C", str(candidate), "config", "user.email", "test@example.com"], check=True)
        subprocess.run(["git", "-C", str(candidate), "config", "user.name", "Test"], check=True)
        (candidate / "README.md").write_text("baseline\n", encoding="utf-8")
        (candidate / ".gitignore").write_text(".devteam/\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(candidate), "add", "."], check=True)
        subprocess.run(["git", "-C", str(candidate), "commit", "-qm", "baseline"], check=True)
        subprocess.run(["git", "-C", str(candidate), "branch", "-M", "main"], check=True)

        common_hooks = work / "common" / "hooks"
        common_hooks.mkdir(parents=True)
        bundle_root, digest = installer.install_trusted_bundle(ROOT, common_hooks)
        manifest_path, closure_digest = installer.install_interpreter_closure_manifest(
            Path(sys.executable), bundle_root / "scripts" / "review_gate.py", bundle_root
        )
        python_blob = subprocess.run(
            ["git", "hash-object", "--no-filters", "--", sys.executable],
            check=True, capture_output=True, text=True, encoding="utf-8",
        ).stdout.strip()
        for key, value in (
            ("ai-company.pythonExecutable", sys.executable),
            ("ai-company.pythonExecutableBlob", python_blob),
            ("ai-company.trustedReviewGatePath", str(bundle_root / "scripts" / "review_gate.py")),
            ("ai-company.trustedReviewGateDigest", digest),
            ("ai-company.pythonInterpreterClosureDigest", closure_digest),
        ):
            subprocess.run(["git", "-C", str(candidate), "config", "--local", key, value], check=True)

        launcher = bundle_root / "scripts" / "trusted_gate_launcher.ps1"
        command = [
            "powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", str(launcher),
            "-TargetRoot", str(candidate), "-Command", "identity-issue",
            "--run-id", "113e4567-e89b-12d3-a456-426614174002",
            "--invocation-id", "213e4567-e89b-12d3-a456-426614174002",
            "--role", "reviewer", "--provider", "openai", "--model", "gpt-5.6-sol",
            "--runner-instance-id", "313e4567-e89b-12d3-a456-426614174002",
        ]

        # Positive: untampered closure verifies and the gate runs.
        accepted = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert accepted.returncode == 0, accepted.stdout + accepted.stderr

        # Wrong-but-well-formed digest is rejected.
        subprocess.run(
            ["git", "-C", str(candidate), "config", "--local", "ai-company.pythonInterpreterClosureDigest", "a" * 64],
            check=True,
        )
        wrong = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert wrong.returncode == 1
        assert "does not match its pinned closure digest" in wrong.stderr

        # Invalid-format digest is rejected before any comparison.
        subprocess.run(
            ["git", "-C", str(candidate), "config", "--local", "ai-company.pythonInterpreterClosureDigest", "not-hex"],
            check=True,
        )
        invalid = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert invalid.returncode == 1
        assert "interpreter-closure digest is invalid" in invalid.stderr

        # Restore the correct digest, then tamper the manifest content itself (not the pinned
        # config value): this changes what the launcher hashes without updating what it expects.
        subprocess.run(
            ["git", "-C", str(candidate), "config", "--local", "ai-company.pythonInterpreterClosureDigest", closure_digest],
            check=True,
        )
        original_manifest_bytes = manifest_path.read_bytes()
        manifest_obj = json.loads(original_manifest_bytes.decode("utf-8"))
        manifest_obj["files"].append("Lib/os.py")
        manifest_path.write_text(json.dumps(manifest_obj), encoding="utf-8")
        try:
            tampered = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
            assert tampered.returncode == 1
            assert "does not match its pinned closure digest" in tampered.stderr
        finally:
            manifest_path.write_bytes(original_manifest_bytes)

        # Missing manifest is rejected with a distinct message.
        manifest_path.unlink()
        try:
            missing = subprocess.run(command, capture_output=True, text=True, encoding="utf-8", errors="replace")
            assert missing.returncode == 1
            assert "Interpreter-closure manifest is unavailable" in missing.stderr
        finally:
            manifest_path.write_bytes(original_manifest_bytes)

        # Restored: the launcher accepts again (fresh run/invocation ids -- the earlier
        # "accepted" call already recorded an immutable identity for the original ids).
        restored_command = [*command]
        restored_command[restored_command.index("113e4567-e89b-12d3-a456-426614174002")] = "113e4567-e89b-12d3-a456-426614174003"
        restored_command[restored_command.index("213e4567-e89b-12d3-a456-426614174002")] = "213e4567-e89b-12d3-a456-426614174003"
        restored_command[restored_command.index("313e4567-e89b-12d3-a456-426614174002")] = "313e4567-e89b-12d3-a456-426614174003"
        restored = subprocess.run(restored_command, capture_output=True, text=True, encoding="utf-8", errors="replace")
        assert restored.returncode == 0, restored.stdout + restored.stderr
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_distribution_interpreter_binding_matches_installed_executable():
    configured = subprocess.run(
        ["git", "-C", str(ROOT), "config", "--local", "--get", "ai-company.pythonExecutable"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    configured_blob = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "config",
            "--local",
            "--get",
            "ai-company.pythonExecutableBlob",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert configured.returncode == 0 and configured.stdout.strip()
    assert configured_blob.returncode == 0 and configured_blob.stdout.strip()
    observed_blob = subprocess.run(
        [
            "git",
            "-C",
            str(ROOT),
            "hash-object",
            "--no-filters",
            "--",
            configured.stdout.strip(),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert observed_blob.returncode == 0
    assert observed_blob.stdout.strip() == configured_blob.stdout.strip()


def test_distribution_cli_is_executable():
    result = subprocess.run(
        [sys.executable, "-B", str(ROOT / "scripts" / "review_gate.py"), "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "trusted-bundle-check" in result.stdout
