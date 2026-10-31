"""Stdlib-only closed JSON Schema Draft 2020-12 subset for Role Component contracts."""
from __future__ import annotations

import json
import math
import re
import uuid
from datetime import datetime
from pathlib import Path
from typing import Mapping, Sequence


DRAFT_2020_12 = "https://json-schema.org/draft/2020-12/schema"
SUPPORTED_KEYWORDS = frozenset(
    {
        "$defs",
        "$id",
        "$ref",
        "$schema",
        "additionalProperties",
        "allOf",
        "anyOf",
        "const",
        "description",
        "enum",
        "format",
        "items",
        "maximum",
        "maxItems",
        "maxLength",
        "minimum",
        "minItems",
        "minLength",
        "oneOf",
        "pattern",
        "properties",
        "required",
        "title",
        "type",
        "uniqueItems",
    }
)
SUPPORTED_FORMATS = frozenset({"date-time", "semver", "sha256", "uuid"})
SUPPORTED_TYPES = frozenset({"array", "boolean", "integer", "null", "number", "object", "string"})


class SchemaProfileError(ValueError):
    """A schema uses an unknown or malformed construct outside the closed profile."""


class ContractValidationError(ValueError):
    """An instance does not satisfy its contract schema."""

    def __init__(self, issues: Sequence[str]):
        self.issues = tuple(issues)
        super().__init__("contract validation failed: " + "; ".join(self.issues))


def _json_key(value: object) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _schema_children(schema: Mapping[str, object]) -> list[tuple[str, object]]:
    children = []
    for key in ("properties", "$defs"):
        value = schema.get(key, {})
        if isinstance(value, dict):
            children.extend((f"{key}/{name}", child) for name, child in value.items())
    for key in ("items", "additionalProperties"):
        value = schema.get(key)
        if isinstance(value, dict):
            children.append((key, value))
    for key in ("allOf", "anyOf", "oneOf"):
        value = schema.get(key, [])
        if isinstance(value, list):
            children.extend((f"{key}/{index}", child) for index, child in enumerate(value))
    return children


def validate_schema(schema: Mapping[str, object], *, require_root_metadata: bool = False) -> None:
    """Fail closed on every keyword or construct outside the Phase 0B profile."""

    def visit(node: object, path: str) -> None:
        if not isinstance(node, dict):
            raise SchemaProfileError(f"{path}: schema node must be an object")
        unknown = set(node) - SUPPORTED_KEYWORDS
        if unknown:
            raise SchemaProfileError(f"{path}: unsupported schema keyword(s): {sorted(unknown)!r}")
        if "$ref" in node and len(node) != 1:
            raise SchemaProfileError(f"{path}: $ref nodes may not have sibling keywords")
        for key in ("$schema", "$id", "$ref", "title", "description"):
            if key in node and not isinstance(node[key], str):
                raise SchemaProfileError(f"{path}: {key} must be a string")
        schema_type = node.get("type")
        if schema_type is not None and schema_type not in SUPPORTED_TYPES:
            raise SchemaProfileError(f"{path}: unsupported type {schema_type!r}")
        schema_format = node.get("format")
        if schema_format is not None and schema_format not in SUPPORTED_FORMATS:
            raise SchemaProfileError(f"{path}: unsupported format {schema_format!r}")
        if "required" in node and (
            not isinstance(node["required"], list)
            or not all(isinstance(item, str) for item in node["required"])
            or len(set(node["required"])) != len(node["required"])
        ):
            raise SchemaProfileError(f"{path}: required must be a unique string array")
        for key in ("properties", "$defs"):
            if key in node and not isinstance(node[key], dict):
                raise SchemaProfileError(f"{path}: {key} must be an object")
        for key in ("allOf", "anyOf", "oneOf"):
            if key in node and (not isinstance(node[key], list) or not node[key]):
                raise SchemaProfileError(f"{path}: {key} must be a non-empty array")
        if "additionalProperties" in node and not isinstance(node["additionalProperties"], (bool, dict)):
            raise SchemaProfileError(f"{path}: additionalProperties must be boolean or schema")
        if "items" in node and not isinstance(node["items"], dict):
            raise SchemaProfileError(f"{path}: items must be a schema object")
        if "uniqueItems" in node and not isinstance(node["uniqueItems"], bool):
            raise SchemaProfileError(f"{path}: uniqueItems must be boolean")
        if "enum" in node and (not isinstance(node["enum"], list) or not node["enum"]):
            raise SchemaProfileError(f"{path}: enum must be a non-empty array")
        for key in ("minLength", "maxLength", "minItems", "maxItems"):
            if key in node and (
                not isinstance(node[key], int) or isinstance(node[key], bool) or node[key] < 0
            ):
                raise SchemaProfileError(f"{path}: {key} must be a non-negative integer")
        for key in ("minimum", "maximum"):
            if key in node and (
                not isinstance(node[key], (int, float)) or isinstance(node[key], bool)
            ):
                raise SchemaProfileError(f"{path}: {key} must be a number")
        if "pattern" in node:
            if not isinstance(node["pattern"], str):
                raise SchemaProfileError(f"{path}: pattern must be a string")
            try:
                re.compile(node["pattern"])
            except re.error as exc:
                raise SchemaProfileError(f"{path}: invalid pattern: {exc}") from exc
        for name, child in _schema_children(node):
            visit(child, f"{path}/{name}")

    if not isinstance(schema, dict):
        raise SchemaProfileError("$: root schema must be an object")
    if require_root_metadata:
        if schema.get("$schema") != DRAFT_2020_12:
            raise SchemaProfileError("$: root $schema must declare Draft 2020-12")
        if not isinstance(schema.get("$id"), str) or not schema["$id"]:
            raise SchemaProfileError("$: root $id must be a non-empty string")
    visit(schema, "$")


class SchemaRegistry:
    """A deterministic registry keyed by exact schema $id values."""

    def __init__(self) -> None:
        self._schemas: dict[str, dict[str, object]] = {}

    def register(self, schema: Mapping[str, object]) -> None:
        validate_schema(schema, require_root_metadata=True)
        schema_id = str(schema["$id"])
        if schema_id in self._schemas:
            raise SchemaProfileError(f"duplicate schema $id: {schema_id}")
        detached = json.loads(
            json.dumps(
                schema,
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
        )
        assert isinstance(detached, dict)
        self._schemas[schema_id] = detached

    @classmethod
    def from_directory(cls, directory: str | Path) -> "SchemaRegistry":
        registry = cls()
        paths = sorted(Path(directory).glob("*.schema.json"))
        if not paths:
            raise SchemaProfileError(f"no *.schema.json files found in {directory}")
        for path in paths:
            try:
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SchemaProfileError(f"cannot load schema {path}: {exc}") from exc
            if not isinstance(value, dict):
                raise SchemaProfileError(f"schema root is not an object: {path}")
            registry.register(value)
        for schema in registry._schemas.values():
            registry.validate_references(schema)
        return registry

    def get(self, schema_id: str) -> dict[str, object]:
        try:
            return json.loads(
                json.dumps(
                    self._schemas[schema_id],
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                )
            )
        except KeyError as exc:
            raise SchemaProfileError(f"unresolved schema $id: {schema_id}") from exc

    def snapshot(self) -> "SchemaRegistry":
        """Return an independent registry with detached canonical schema objects."""

        detached = SchemaRegistry()
        for schema_id in sorted(self._schemas):
            detached.register(self._schemas[schema_id])
        return detached

    def resolve(
        self,
        reference: str,
        current_root: Mapping[str, object],
    ) -> tuple[dict[str, object], dict[str, object]]:
        base, separator, fragment = reference.partition("#")
        root = dict(current_root) if not base else self.get(base)
        target: object = root
        if separator and fragment:
            if not fragment.startswith("/"):
                raise SchemaProfileError(f"unsupported non-pointer fragment: #{fragment}")
            for raw in fragment[1:].split("/"):
                token = raw.replace("~1", "/").replace("~0", "~")
                if not isinstance(target, dict) or token not in target:
                    raise SchemaProfileError(f"unresolved JSON pointer in $ref: {reference}")
                target = target[token]
        if not isinstance(target, dict):
            raise SchemaProfileError(f"$ref target is not a schema object: {reference}")
        return target, root

    def validate_references(self, schema: Mapping[str, object]) -> None:
        """Resolve every reachable reference once, including cyclic reference graphs."""

        validate_schema(schema)
        visited_refs: set[tuple[str, str]] = set()

        def visit(node: Mapping[str, object], root: Mapping[str, object]) -> None:
            if "$ref" in node:
                reference = str(node["$ref"])
                key = (str(root.get("$id", "")), reference)
                if key in visited_refs:
                    return
                visited_refs.add(key)
                target, target_root = self.resolve(reference, root)
                visit(target, target_root)
                return
            for _, child in _schema_children(node):
                if isinstance(child, dict):
                    visit(child, root)

        visit(schema, schema)


def _matches_type(instance: object, schema_type: str) -> bool:
    if schema_type == "null":
        return instance is None
    if schema_type == "boolean":
        return isinstance(instance, bool)
    if schema_type == "integer":
        return isinstance(instance, int) and not isinstance(instance, bool)
    if schema_type == "number":
        return (
            isinstance(instance, (int, float))
            and not isinstance(instance, bool)
            and (not isinstance(instance, float) or math.isfinite(instance))
        )
    if schema_type == "string":
        return isinstance(instance, str)
    if schema_type == "array":
        return isinstance(instance, list)
    if schema_type == "object":
        return isinstance(instance, dict)
    raise SchemaProfileError(f"unsupported type at runtime: {schema_type}")


def _format_valid(value: str, schema_format: str) -> bool:
    if schema_format == "uuid":
        try:
            return str(uuid.UUID(value)) == value.lower()
        except ValueError:
            return False
    if schema_format == "date-time":
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            return parsed.tzinfo is not None
        except ValueError:
            return False
    if schema_format == "sha256":
        return re.fullmatch(r"[0-9a-f]{64}", value) is not None
    if schema_format == "semver":
        return (
            re.fullmatch(
                r"(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)"
                r"(?:-(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*)"
                r"(?:\.(?:0|[1-9]\d*|\d*[A-Za-z-][0-9A-Za-z-]*))*)?"
                r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?",
                value,
            )
            is not None
        )
    raise SchemaProfileError(f"unsupported format at runtime: {schema_format}")


def validate_instance(
    instance: object,
    schema: Mapping[str, object],
    *,
    registry: SchemaRegistry | None = None,
) -> None:
    """Validate one JSON value and raise all deterministic issues in path order."""

    validate_schema(schema)
    try:
        _json_key(instance)
    except (TypeError, ValueError) as exc:
        raise ContractValidationError(["$: instance is not a finite JSON value"]) from exc
    active_registry = registry or SchemaRegistry()
    issues: list[str] = []

    def check(
        value: object,
        node: Mapping[str, object],
        root: Mapping[str, object],
        path: str,
        sink: list[str],
    ) -> None:
        if "$ref" in node:
            target, target_root = active_registry.resolve(str(node["$ref"]), root)
            check(value, target, target_root, path, sink)
            return

        for keyword in ("allOf", "anyOf", "oneOf"):
            if keyword not in node:
                continue
            branch_results = []
            for branch in node[keyword]:  # type: ignore[index]
                branch_issues: list[str] = []
                check(value, branch, root, path, branch_issues)
                branch_results.append(branch_issues)
            matches = sum(not result for result in branch_results)
            if keyword == "allOf" and matches != len(branch_results):
                sink.append(f"{path}: does not satisfy allOf")
            elif keyword == "anyOf" and matches == 0:
                sink.append(f"{path}: does not satisfy anyOf")
            elif keyword == "oneOf" and matches != 1:
                sink.append(f"{path}: satisfies {matches} oneOf branches, expected exactly one")

        schema_type = node.get("type")
        if isinstance(schema_type, str) and not _matches_type(value, schema_type):
            sink.append(f"{path}: expected {schema_type}, observed {type(value).__name__}")
            return
        if "const" in node and _json_key(value) != _json_key(node["const"]):
            sink.append(f"{path}: value does not equal const")
        if "enum" in node:
            enum_keys = {_json_key(item) for item in node["enum"]}  # type: ignore[index]
            if _json_key(value) not in enum_keys:
                sink.append(f"{path}: value is not in enum")

        if isinstance(value, dict):
            required = node.get("required", [])
            for name in required:  # type: ignore[assignment]
                if name not in value:
                    sink.append(f"{path}: missing required property {name!r}")
            properties = node.get("properties", {})
            for name, child in properties.items():  # type: ignore[union-attr]
                if name in value:
                    check(value[name], child, root, f"{path}/{name}", sink)
            extras = sorted(set(value) - set(properties))  # type: ignore[arg-type]
            additional = node.get("additionalProperties", True)
            if additional is False:
                sink.extend(f"{path}: additional property {name!r} is forbidden" for name in extras)
            elif isinstance(additional, dict):
                for name in extras:
                    check(value[name], additional, root, f"{path}/{name}", sink)
        elif isinstance(value, list):
            if "minItems" in node and len(value) < node["minItems"]:  # type: ignore[operator]
                sink.append(f"{path}: fewer than minItems")
            if "maxItems" in node and len(value) > node["maxItems"]:  # type: ignore[operator]
                sink.append(f"{path}: more than maxItems")
            if node.get("uniqueItems") and len({_json_key(item) for item in value}) != len(value):
                sink.append(f"{path}: array items are not unique")
            if isinstance(node.get("items"), dict):
                for index, item in enumerate(value):
                    check(item, node["items"], root, f"{path}/{index}", sink)  # type: ignore[arg-type]
        elif isinstance(value, str):
            if "minLength" in node and len(value) < node["minLength"]:  # type: ignore[operator]
                sink.append(f"{path}: shorter than minLength")
            if "maxLength" in node and len(value) > node["maxLength"]:  # type: ignore[operator]
                sink.append(f"{path}: longer than maxLength")
            if "pattern" in node and re.search(str(node["pattern"]), value) is None:
                sink.append(f"{path}: does not match pattern")
            if "format" in node and not _format_valid(value, str(node["format"])):
                sink.append(f"{path}: invalid {node['format']} format")
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            if "minimum" in node and value < node["minimum"]:  # type: ignore[operator]
                sink.append(f"{path}: less than minimum")
            if "maximum" in node and value > node["maximum"]:  # type: ignore[operator]
                sink.append(f"{path}: greater than maximum")

    check(instance, schema, schema, "$", issues)
    if issues:
        raise ContractValidationError(sorted(issues))
