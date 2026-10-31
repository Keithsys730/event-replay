"""Deterministic orchestration and workspace-safety primitives.

Public symbols are resolved lazily so a portable consumer can install only the
orchestration modules required by its declared distribution package.
"""
from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORT_MODULES = {
    "AuditBaseline": ".workspace",
    "ClarificationState": ".discovery",
    "DiscoveryInputError": ".discovery",
    "DiscoveryOutputError": ".discovery",
    "DiscoveryRuntimeError": ".discovery",
    "AuditResult": ".workspace",
    "ExpectedState": ".workspace",
    "FeedbackStateError": ".feedback_state",
    "FeedbackStore": ".feedback_state",
    "LeaseConflict": ".workspace",
    "LeaseHandle": ".workspace",
    "LeaseOwnershipError": ".workspace",
    "PanelSelection": ".review_state",
    "ProviderExecutionError": ".provider_execution",
    "ProviderAdapterFactory": ".provider_execution",
    "QualificationEvidenceStore": ".qualification_state",
    "QualificationStateError": ".qualification_state",
    "ReviewStateError": ".review_state",
    "ReviewStateStore": ".review_state",
    "RoutingDecisionStore": ".routing_state",
    "RoutingStateError": ".routing_state",
    "SourceBinding": ".review_state",
    "StaleLeaseRequiresHumanGate": ".workspace",
    "StateDriftError": ".workspace",
    "acquire_lease": ".workspace",
    "begin_audit": ".workspace",
    "assemble_materialized_evidence": ".discovery",
    "capture_expected_state": ".workspace",
    "execute_provider_invocation": ".provider_execution",
    "finish_audit": ".workspace",
    "load_lease": ".workspace",
    "clarification_state": ".discovery",
    "next_clarification_state": ".discovery",
    "release_lease": ".workspace",
    "renew_lease": ".workspace",
    "resolve_common_dir": ".workspace",
    "select_review_panel": ".review_state",
    "verify_expected_state": ".workspace",
    "validate_discovery_response": ".discovery",
    "validate_discovery_input_v2": ".discovery",
    "validate_discovery_output_v2": ".discovery",
}

__all__ = sorted(_EXPORT_MODULES)


def __getattr__(name: str) -> Any:
    module_name = _EXPORT_MODULES.get(name)
    if module_name is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    value = getattr(import_module(module_name, __name__), name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(__all__))
