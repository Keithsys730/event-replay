"""Provider-neutral RoleRunner contract validation.

Public symbols are resolved lazily so consumers do not import unrelated runtime
capabilities merely by loading one declared submodule.
"""
from __future__ import annotations

from importlib import import_module
from typing import Any


_EXPORT_MODULES = {
    "ContractValidationError": ".schema",
    "EnvelopeSemanticError": ".envelopes",
    "IdempotencyConflict": ".idempotency",
    "IdempotencyDecision": ".idempotency",
    "IdempotencyReservation": ".idempotency",
    "IdempotencyStore": ".idempotency",
    "PackageValidationError": ".package",
    "PackageValidationResult": ".package",
    "SchemaProfileError": ".schema",
    "SchemaRegistry": ".schema",
    "snapshot_package_validation_result": ".package",
    "validate_input_envelope": ".envelopes",
    "validate_instance": ".schema",
    "validate_output_envelope": ".envelopes",
    "validate_package": ".package",
    "validate_schema": ".schema",
    "verify_package_validation_result": ".package",
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
