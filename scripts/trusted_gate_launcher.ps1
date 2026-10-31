[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [string]$TargetRoot,

    [Parameter(Mandatory)]
    [ValidateSet('identity-issue', 'record', 'finalize', 'check', 'attestation-template', 'attestation-check')]
    [string]$Command,

    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$GateArguments
)

# This script is installed inside the digest-pinned trusted-review-gate bundle.  It is the only
# supported operational launcher for v1 commands: it deliberately never resolves candidate Python
# code or imports from Python's site-packages before the trusted bundle verification has passed.
$ErrorActionPreference = 'Stop'

function Stop-TrustedGate([string]$Message) {
    throw "trusted-review-gate: $Message"
}

function Get-ResolvedPath([string]$Path, [string]$Description) {
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -and $Path -notmatch '^\\\\') {
        Stop-TrustedGate "$Description must be an absolute path."
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        Stop-TrustedGate "$Description is unavailable."
    }
    return [IO.Path]::GetFullPath((Resolve-Path -LiteralPath $Path -ErrorAction Stop).Path).TrimEnd('\', '/')
}

function Test-PathContainedBy([string]$Child, [string]$Parent) {
    $prefix = $Parent.TrimEnd('\', '/') + [IO.Path]::DirectorySeparatorChar
    return $Child.Equals($Parent, [StringComparison]::OrdinalIgnoreCase) -or
        $Child.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Test-ForbiddenPythonStartupFiles([string]$PythonHome) {
    $candidates = @(
        (Join-Path $PythonHome 'pyvenv.cfg'),
        (Join-Path (Split-Path -Parent $PythonHome) 'pyvenv.cfg')
    )
    $candidates += Get-ChildItem -LiteralPath $PythonHome -Filter '*._pth' -File -ErrorAction Stop |
        ForEach-Object { $_.FullName }
    $present = @($candidates | Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    if ($present.Count -gt 0) {
        Stop-TrustedGate 'Configured Python runtime has forbidden venv or ._pth startup files.'
    }
}

try {
    # ORD-0034 / P0-26. GIT_DIR silently overrides -C, so an inherited one redirects EVERY git call
    # below -- including this launcher's own trust-anchor reads. Measured 2026-09-04 in scratch
    # repositories: `git -C A config --local --get ai-company.trustedReviewGateDigest` returns B's
    # value when GIT_DIR names B, so the gate path, the expected bundle digest, the bound Python
    # executable and the interpreter closure digest would all be read from a repository the caller
    # named. The containment assertion below does NOT catch it -- `rev-parse --show-toplevel` still
    # answers correctly under GIT_DIR (measured), so it passes and reassures while the anchors are
    # already redirected.
    #
    # Removed here, before the first git invocation, and inherited by the gate process this script
    # starts. GIT_INDEX_FILE is deliberately NOT removed: ORD-0031's B3 measured that dropping it
    # sends index reads back to .git/index and lets a `git commit --only` edit through unseen.
    # Nothing else is removed (ORD-0034 B14; GIT_INDEX_FILE's survival is B16).
    #
    # CAVEAT -- do NOT read B14's grading past the gate's own read. B14 calls GIT_COMMON_DIR
    # fail-CLOSED, and that was measured on review_gate's staged read (exit 128 -> None ->
    # callers block). It does NOT hold for the anchor reads BELOW. Measured 2026-09-04:
    #   GIT_COMMON_DIR=B/.git git -C A config --local --get ai-company.pythonExecutable
    #     -> B's value, exit 0
    # so under a poisoned GIT_COMMON_DIR every anchor this script trusts -- gate path, expected
    # digest, python executable, its blob pin and the closure digest -- comes from a repository
    # the caller named, and $ResolvedPythonExe is then EXECUTED as the trusted gate. The
    # containment assertion below does not catch it, for exactly the reason it misses GIT_DIR:
    # rev-parse --show-toplevel still answers the real target, so it passes and reassures.
    # That is P0-27's round, not this one -- recorded here because this file is where a reader
    # meets the scrub and would otherwise infer the environment was audited.
    Remove-Item Env:GIT_DIR -ErrorAction SilentlyContinue

    $ResolvedTargetRoot = Get-ResolvedPath $TargetRoot 'Candidate target root'
    if (-not (Test-Path -LiteralPath $ResolvedTargetRoot -PathType Container)) {
        Stop-TrustedGate 'Candidate target root must be a directory.'
    }

    $GitExe = if ($env:AI_COMPANY_GIT_BIN -and (Test-Path -LiteralPath $env:AI_COMPANY_GIT_BIN -PathType Leaf)) {
        $env:AI_COMPANY_GIT_BIN
    } else {
        (Get-Command git -ErrorAction SilentlyContinue).Source
    }
    if ([string]::IsNullOrWhiteSpace($GitExe) -or -not (Test-Path -LiteralPath $GitExe -PathType Leaf)) {
        Stop-TrustedGate 'Trusted system Git executable is unavailable.'
    }
    $savedEap = $ErrorActionPreference
    $ErrorActionPreference = 'SilentlyContinue'
    $rawGitTopLevel = (& $GitExe -C $ResolvedTargetRoot rev-parse --show-toplevel 2>&1)
    $ErrorActionPreference = $savedEap
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rawGitTopLevel)) {
        Stop-TrustedGate 'Candidate target root is not a Git repository.'
    }
    $GitTopLevel = ([string]$rawGitTopLevel).Trim()
    $ResolvedGitTopLevel = Get-ResolvedPath $GitTopLevel 'Git repository top-level'
    if (-not $ResolvedTargetRoot.Equals($ResolvedGitTopLevel, [StringComparison]::OrdinalIgnoreCase)) {
        Stop-TrustedGate 'Candidate target root must equal the Git repository top-level.'
    }

    function Get-TrustedConfigAnchor([string]$Key) {
        $raw = & $GitExe -C $ResolvedTargetRoot config --local --get $Key
        if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($raw)) {
            Stop-TrustedGate "Required trust anchor '$Key' is absent or empty in repository config."
        }
        return ([string]$raw).Trim()
    }

    $PythonExe = Get-TrustedConfigAnchor 'ai-company.pythonExecutable'
    $ResolvedPythonExe = Get-ResolvedPath $PythonExe 'Configured Python executable'
    if (-not (Test-Path -LiteralPath $ResolvedPythonExe -PathType Leaf)) {
        Stop-TrustedGate 'Configured Python executable must be a file.'
    }
    if (Test-PathContainedBy $ResolvedPythonExe $ResolvedGitTopLevel) {
        Stop-TrustedGate 'Configured Python executable must not be inside the candidate target root.'
    }
    $PythonHome = Split-Path -Parent $ResolvedPythonExe
    Test-ForbiddenPythonStartupFiles $PythonHome
    $PythonLib = Join-Path $PythonHome 'Lib'
    $PythonDlls = Join-Path $PythonHome 'DLLs'
    if (-not (Test-Path -LiteralPath (Join-Path $PythonLib 'os.py') -PathType Leaf) -or
        -not (Test-Path -LiteralPath $PythonDlls -PathType Container)) {
        Stop-TrustedGate 'Configured Python runtime is not a canonical base interpreter.'
    }

    $PythonBlob = Get-TrustedConfigAnchor 'ai-company.pythonExecutableBlob'
    $rawObservedPythonBlob = & $GitExe -C $ResolvedTargetRoot hash-object --no-filters -- $ResolvedPythonExe
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($rawObservedPythonBlob)) {
        Stop-TrustedGate 'Configured Python executable does not match its installed identity.'
    }
    $ObservedPythonBlob = ([string]$rawObservedPythonBlob).Trim()
    if ($PythonBlob -notmatch '^(?:[0-9a-f]{40}|[0-9a-f]{64})$' -or $ObservedPythonBlob -ne $PythonBlob) {
        Stop-TrustedGate 'Configured Python executable does not match its installed identity.'
    }

    # HIGH (cross-model review, round 3): the .exe is blob-pinned above, but nothing previously
    # verified the Lib/DLLs directory content that sys.path is about to be pointed at -- reviewer
    # B proved arbitrary code execution in the trust chain by shadowing hashlib (used by
    # trusted_bundle_digest() itself) with a fake module in that per-user-writable directory.
    # This verification MUST happen here, in PowerShell/.NET, and MUST complete before any Python
    # process runs: verifying it via a Python subprocess would use the very hashlib the attack
    # targets, so a compromised hashlib could simply lie about its own compromise.
    $ClosureDigest = Get-TrustedConfigAnchor 'ai-company.pythonInterpreterClosureDigest'
    if ($ClosureDigest -notmatch '^[0-9a-f]{64}$') {
        Stop-TrustedGate 'Configured interpreter-closure digest is invalid.'
    }
    $BundleRoot = Split-Path -Parent $PSScriptRoot
    $ClosureManifestPath = Join-Path $BundleRoot 'interpreter-closure-manifest.json'
    if (-not (Test-Path -LiteralPath $ClosureManifestPath -PathType Leaf)) {
        Stop-TrustedGate 'Interpreter-closure manifest is unavailable.'
    }
    $ClosureManifestBytes = [System.IO.File]::ReadAllBytes($ClosureManifestPath)
    try {
        $ClosureManifestObj = [System.Text.Encoding]::UTF8.GetString($ClosureManifestBytes) | ConvertFrom-Json -ErrorAction Stop
    } catch {
        Stop-TrustedGate 'Interpreter-closure manifest is not valid JSON.'
    }
    $ClosureFiles = @($ClosureManifestObj.files)
    if ($ClosureFiles.Count -eq 0) {
        Stop-TrustedGate 'Interpreter-closure manifest lists no files.'
    }
    $ClosureSha256 = [System.Security.Cryptography.SHA256]::Create()
    $ClosureStream = New-Object System.IO.MemoryStream
    try {
        $ManifestNameBytes = [System.Text.Encoding]::UTF8.GetBytes('interpreter-closure-manifest.json')
        $ClosureStream.Write($ManifestNameBytes, 0, $ManifestNameBytes.Length)
        $ClosureStream.WriteByte(0)
        $ClosureStream.Write($ClosureManifestBytes, 0, $ClosureManifestBytes.Length)
        $ClosureStream.WriteByte(0)
        foreach ($relative in $ClosureFiles) {
            $relativeStr = [string]$relative
            if ([string]::IsNullOrWhiteSpace($relativeStr) -or $relativeStr.Contains('..') -or
                [System.IO.Path]::IsPathRooted($relativeStr)) {
                Stop-TrustedGate "Interpreter-closure manifest contains an unsafe path: $relativeStr"
            }
            $memberPath = Join-Path $PythonHome ($relativeStr -replace '/', '\')
            if (-not (Test-Path -LiteralPath $memberPath -PathType Leaf)) {
                Stop-TrustedGate "Interpreter-closure member is missing: $relativeStr"
            }
            $relBytes = [System.Text.Encoding]::UTF8.GetBytes($relativeStr)
            $ClosureStream.Write($relBytes, 0, $relBytes.Length)
            $ClosureStream.WriteByte(0)
            $memberBytes = [System.IO.File]::ReadAllBytes($memberPath)
            $ClosureStream.Write($memberBytes, 0, $memberBytes.Length)
            $ClosureStream.WriteByte(0)
        }
        $ComputedClosureDigest = ([BitConverter]::ToString($ClosureSha256.ComputeHash($ClosureStream.ToArray())) -replace '-', '').ToLowerInvariant()
    } finally {
        $ClosureStream.Dispose()
        $ClosureSha256.Dispose()
    }
    if ($ComputedClosureDigest -ne $ClosureDigest) {
        Stop-TrustedGate 'Interpreter Lib/DLLs content does not match its pinned closure digest.'
    }

    $rawProbe = & $ResolvedPythonExe -I -S -B -c "import sys; print('AI_COMPANY_CPYTHON_OK' if sys.implementation.name == 'cpython' and sys.version_info[:2] >= (3, 11) and sys.flags.optimize == 0 and sys.flags.no_site else 'INVALID')" 2>$null
    $Probe = if ($null -ne $rawProbe) { ([string]$rawProbe).Trim() } else { '' }
    if ($LASTEXITCODE -ne 0 -or $Probe -ne 'AI_COMPANY_CPYTHON_OK') {
        Stop-TrustedGate 'Configured Python executable failed the CPython no-site probe.'
    }

    $ConfiguredGate = Get-TrustedConfigAnchor 'ai-company.trustedReviewGatePath'
    $TrustedGateDigest = Get-TrustedConfigAnchor 'ai-company.trustedReviewGateDigest'
    $TrustedGatePath = Get-ResolvedPath $ConfiguredGate 'Configured trusted review-gate path'
    $ExpectedGatePath = Get-ResolvedPath (Join-Path $PSScriptRoot 'review_gate.py') 'Installed trusted review-gate path'
    if (-not $TrustedGatePath.Equals($ExpectedGatePath, [StringComparison]::OrdinalIgnoreCase)) {
        Stop-TrustedGate 'Configured trusted review-gate path does not match this installed launcher bundle.'
    }
    if ($TrustedGateDigest -notmatch '^[0-9a-f]{64}$') {
        Stop-TrustedGate 'Configured trusted review-gate digest is invalid.'
    }

    # -S prevents site initialization (.pth execution); the explicit stdlib-only path prevents
    # ambient/candidate imports.  Arguments, including the target root, are passed without shell
    # interpolation to every invocation.  -B (round 4 cross-model review): the closure digest above
    # now pins __pycache__/*.pyc content, so a run that let CPython rewrite a legitimately-stale
    # pyc would silently invalidate that pin on the very next commit; -B keeps every pinned pyc's
    # on-disk bytes unchanged (CPython still transparently recompiles the source in memory).
    $Bootstrap = "import os,runpy,sys; target,gate,lib,dlls,*args=sys.argv[1:]; os.environ['AI_COMPANY_GATE_TARGET_ROOT']=target; sys.path[:]=[lib,dlls]; sys.argv=[gate,*args]; runpy.run_path(gate,run_name='__main__')"
    & $ResolvedPythonExe -I -S -B -c $Bootstrap $ResolvedGitTopLevel $TrustedGatePath $PythonLib $PythonDlls trusted-bundle-check --expected-digest $TrustedGateDigest
    if ($LASTEXITCODE -ne 0) { Stop-TrustedGate 'Trusted gate bundle verification failed.' }
    & $ResolvedPythonExe -I -S -B -c $Bootstrap $ResolvedGitTopLevel $TrustedGatePath $PythonLib $PythonDlls $Command @GateArguments
    exit $LASTEXITCODE
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
