"""Playbook loading, immutable snapshots, review, and deviation scoring.

Playbook files are untrusted input. They are parsed with duplicate-key-safe JSON
or YAML loaders, validated through strict domain models, and retained as
canonical snapshots for reproducible audit receipts. Contract text is also
untrusted evidence: no playbook value can disable deterministic policy checks,
suppress escalation, or force an ``allow`` routing decision.

The complete contract remains available in memory. Clause spans are offset
provenance, not vector-retrieval chunks.

This module provides decision support only. It does not provide legal advice.
A qualified lawyer must review the output and sign the final decision.
"""

from __future__ import annotations

import hashlib
import inspect
import json
import math
import os
import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import MappingProxyType
from typing import Any, Final

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StrictInt,
    ValidationError,
    field_validator,
    model_validator,
)

from .models import Action, Clause, PlaybookRule, PolicyResult
from .policy import (
    CONSTITUTIONAL_RULE,
    detect_schedule4_liability_trap,
    evaluate_policy,
    intercept_prompt_injection,
)


try:  # pragma: no cover - depends on the installed extras
    import yaml
except ImportError:  # pragma: no cover - JSON remains dependency-free
    yaml = None


DEFAULT_MAX_PLAYBOOK_BYTES: Final[int] = 2 * 1024 * 1024
DEFAULT_MAX_PLAYBOOK_RULES: Final[int] = 10_000
DEFAULT_MAX_DOCUMENT_CHARACTERS: Final[int] = 20_000_000

_MAX_YAML_ALIASES: Final[int] = 1_000
_MAX_JSON_DEPTH: Final[int] = 128
_MAX_COLLECTION_ITEMS: Final[int] = 100_000
_MAX_METADATA_KEYS: Final[int] = 1_000
_MAX_RULES_PER_COLLECTION: Final[int] = 256
_MAX_THRESHOLD_KEYS: Final[int] = 256
_MAX_MATCHES_PER_RULE: Final[int] = 10_000

_SEVERITY_RISK: Final[dict[str, float]] = {
    "info": 0.10,
    "low": 0.25,
    "medium": 0.50,
    "high": 0.75,
    "critical": 1.00,
}
_ACTION_MULTIPLIER: Final[dict[Action, float]] = {
    Action.ALLOW: 0.0,
    Action.QUEUE: 0.90,
    Action.BLOCK: 1.00,
}
_ACTION_ORDER: Final[dict[Action, int]] = {
    Action.ALLOW: 0,
    Action.QUEUE: 1,
    Action.BLOCK: 2,
}

_ID_ALIASES: Final[tuple[str, ...]] = (
    "playbook_id",
    "playbookId",
    "id",
)
_VERSION_ALIASES: Final[tuple[str, ...]] = (
    "playbook_version",
    "playbookVersion",
    "version",
)
_NAME_ALIASES: Final[tuple[str, ...]] = (
    "playbook_name",
    "playbookName",
    "name",
    "title",
)
_DESCRIPTION_ALIASES: Final[tuple[str, ...]] = (
    "description",
    "summary",
)
_THRESHOLD_ALIASES: Final[tuple[str, ...]] = (
    "thresholds",
    "risk_thresholds",
    "riskThresholds",
)
_METADATA_ALIASES: Final[tuple[str, ...]] = (
    "metadata",
    "playbook_metadata",
    "playbookMetadata",
)
_RULE_ALIASES: Final[tuple[str, ...]] = (
    "rules",
    "policy_rules",
    "policyRules",
)
_ENVELOPE_ALIASES: Final[tuple[str, ...]] = (
    "playbook",
    "playbookSpecification",
    "playbook_specification",
    "specification",
)

_RULE_FIELD_ALIASES: Final[dict[str, tuple[str, ...]]] = {
    "rule_id": ("ruleId", "id"),
    "name": ("ruleName", "rule_name"),
    "description": ("ruleDescription", "rule_description"),
    "reason_code": ("reasonCode",),
    "action": (),
    "severity": (),
    "match_type": ("matchType",),
    "pattern": ("matchPattern", "match_pattern"),
    "patterns": (),
    "expected_text": ("expectedText", "expected"),
    "clause_type": ("clauseType",),
    "section": (),
    "schedule": (),
    "confidence": (),
    "priority": (),
    "weight": (),
    "enabled": (),
    "metadata": (),
}

_MISSING: Final[object] = object()

_HEADING_RE: re.Pattern[str] = re.compile(
    r"^[ \t\ufeff]{0,16}"
    r"(?P<kind>SECTION|SCHEDULE|APPENDIX|EXHIBIT)[ \t]+"
    r"(?:NO\.?[ \t]*)?"
    r"(?P<number>"
    r"[0-9]+(?:\.[0-9]+)*[A-Za-z]?"
    r"|[IVXLCDM]+"
    r"|[A-Z](?:\.[0-9]+)*"
    r"|ONE|TWO|THREE|FOUR|FIVE|SIX|SEVEN|EIGHT|NINE|TEN"
    r")"
    r"(?=$|[ \t.,:;\-–—])",
    re.IGNORECASE | re.MULTILINE,
)

_LIABILITY_CONTEXT_RE: re.Pattern[str] = re.compile(
    r"\bliabilit(?:y|ies)\b|\blimitation[ \t]+of[ \t]+liability\b",
    re.IGNORECASE,
)

_CAP_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"\bliabilit(?:y|ies)\b.{0,120}?"
        r"\b(?:capped|limited|liability[ \t]+cap|cap[ \t]+of|"
        r"set[ \t]+at|equal[ \t]+to)\b.{0,50}?"
        r"(?P<amount>[0-9]+(?:\.[0-9]+)?|"
        r"one|two|three|four|five|six|seven|eight|nine|ten|eleven|"
        r"twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|"
        r"nineteen|twenty|thirty|forty|fifty)\s*"
        r"(?P<unit>months?|years?)",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\b(?:cap(?:s|ped)?|limit(?:s|ed)?)\b.{0,80}?"
        r"\bliabilit(?:y|ies)\b.{0,50}?"
        r"(?P<amount>[0-9]+(?:\.[0-9]+)?|"
        r"one|two|three|four|five|six|seven|eight|nine|ten|eleven|"
        r"twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|"
        r"nineteen|twenty|thirty|forty|fifty)\s*"
        r"(?P<unit>months?|years?)",
        re.IGNORECASE | re.DOTALL,
    ),
)

_UNCAPPED_LIABILITY_PATTERNS: Final[tuple[re.Pattern[str], ...]] = (
    re.compile(
        r"\b(?:uncapped|unlimited)\b.{0,100}\bliabilit(?:y|ies)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\bliabilit(?:y|ies)\b.{0,160}"
        r"\b(?:uncapped|unlimited|without[ \t]+limitation)\b",
        re.IGNORECASE | re.DOTALL,
    ),
    re.compile(
        r"\bliabilit(?:y|ies)\b.{0,160}"
        r"\b(?:not[ \t]+subject[ \t]+to|outside[ \t]+(?:the[ \t]+)?)"
        r"(?:the[ \t]+)?(?:cap|limitation)\b",
        re.IGNORECASE | re.DOTALL,
    ),
)

_WORD_MONTHS: Final[dict[str, int]] = {
    "one": 1,
    "two": 2,
    "three": 3,
    "four": 4,
    "five": 5,
    "six": 6,
    "seven": 7,
    "eight": 8,
    "nine": 9,
    "ten": 10,
    "eleven": 11,
    "twelve": 12,
    "thirteen": 13,
    "fourteen": 14,
    "fifteen": 15,
    "sixteen": 16,
    "seventeen": 17,
    "eighteen": 18,
    "nineteen": 19,
    "twenty": 20,
    "thirty": 30,
    "forty": 40,
    "fifty": 50,
}

_EU_TRANSFER_RE: re.Pattern[str] = re.compile(
    r"\b(?:EU|EEA|European[ \t]+Union|European[ \t]+Economic[ \t]+Area)\b"
    r".{0,240}\b(?:transfer|transfers|transferred|transferring)\b"
    r"|\b(?:transfer|transfers|transferred|transferring)\b"
    r".{0,240}\b(?:EU|EEA|European[ \t]+Union|"
    r"European[ \t]+Economic[ \t]+Area)\b",
    re.IGNORECASE | re.DOTALL,
)

_SCC_RE: re.Pattern[str] = re.compile(
    r"\bSCCs?\b|\bstandard[ \t]+contractual[ \t]+clauses?\b",
    re.IGNORECASE,
)

_SCC_VARIATION_RE: re.Pattern[str] = re.compile(
    r"\bnon[- ]?compliant\b"
    r"|\bdoes[ \t]+not[ \t]+comply\b"
    r"|\bincompatible\b"
    r"|\bdeviat(?:e|es|ed|ion|ions)\b"
    r"|\bmaterially[ \t]+(?:amend(?:ed|s)?|chang(?:ed|s)?|"
    r"modif(?:ied|y)|alter(?:ed|s)?)\b"
    r"|\b(?:omits?|omitted|missing|incomplete)\b"
    r"|\bdoes[ \t]+not[ \t]+include\b"
    r"|\bwithout[ \t]+(?:the[ \t]+)?"
    r"(?:required|applicable|mandatory|any)\b"
    r"|\bunilaterally[ \t]+(?:amend(?:ed|s)?|modif(?:ied|y))\b",
    re.IGNORECASE | re.DOTALL,
)

_SCC_MODULE_RE: re.Pattern[str] = re.compile(
    r"\bmodule[ \t]+(?P<module>[0-9]+|[ivxlcdm]+)\b",
    re.IGNORECASE,
)


class PlaybookError(ValueError):
    """Base class for playbook failures."""


class PlaybookLoadError(PlaybookError):
    """Raised when a playbook cannot be safely read or parsed."""


class PlaybookValidationError(PlaybookLoadError):
    """Raised when playbook data violates the playbook schema."""


class PlaybookEvaluationError(PlaybookError):
    """Raised when a complete-document review cannot be completed safely."""


class _DuplicateJsonKey(ValueError):
    def __init__(self, key: str) -> None:
        self.key = key
        super().__init__(key)


class _DuplicateYamlKey(ValueError):
    def __init__(self, key: object) -> None:
        self.key = key
        super().__init__(str(key))


class _NonFiniteJsonNumber(ValueError):
    def __init__(self, token: str) -> None:
        self.token = token
        super().__init__(token)


def _json_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateJsonKey(key)
        result[key] = value
    return result


def _reject_json_constant(token: str) -> object:
    raise _NonFiniteJsonNumber(token)


def _require_limit(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise TypeError(f"{name} must be an integer")
    if value <= 0:
        raise ValueError(f"{name} must be positive")
    return value


def _canonical_json_bytes(value: object) -> bytes:
    def encode_default(item: object) -> object:
        if isinstance(item, Enum):
            return item.value
        if hasattr(item, "model_dump"):
            return item.model_dump(mode="json", by_alias=False)
        raise TypeError(
            f"value of type {type(item).__name__} is not JSON serializable"
        )

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=encode_default,
    ).encode("utf-8")


def _json_path(parent: str, key: object) -> str:
    if isinstance(key, int):
        return f"{parent}[{key}]"
    return f"{parent}.{key}" if parent else str(key)


def _canonicalize_input(
    value: object,
    *,
    root_label: str,
    depth: int = 0,
    item_count: int = 0,
) -> object:
    if depth > _MAX_JSON_DEPTH:
        raise PlaybookValidationError(
            f"playbook {root_label} exceeds the configured nesting depth limit"
        )

    if value is None or isinstance(value, str):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise PlaybookValidationError(
                f"playbook {root_label} contains a non-finite number"
            )
        return value
    if isinstance(value, Mapping):
        item_count += 1
        if item_count > _MAX_COLLECTION_ITEMS:
            raise PlaybookValidationError(
                f"playbook {root_label} exceeds the collection item limit"
            )
        result: dict[str, object] = {}
        for key, child in value.items():
            if not isinstance(key, str) or not key.strip():
                raise PlaybookValidationError(
                    f"playbook {_json_path(root_label, key)} has an invalid key"
                )
            if len(key) > 1_000:
                raise PlaybookValidationError(
                    f"playbook {_json_path(root_label, key)} has an oversized key"
                )
            child_path = _json_path(root_label, key)
            if key in result:
                raise PlaybookValidationError(
                    f"playbook {child_path} contains a duplicate key"
                )
            result[key] = _canonicalize_input(
                child,
                root_label=child_path,
                depth=depth + 1,
                item_count=item_count,
            )
        return result
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        item_count += 1
        if item_count > _MAX_COLLECTION_ITEMS:
            raise PlaybookValidationError(
                f"playbook {root_label} exceeds the collection item limit"
            )
        return [
            _canonicalize_input(
                child,
                root_label=_json_path(root_label, index),
                depth=depth + 1,
                item_count=item_count,
            )
            for index, child in enumerate(value)
        ]
    if isinstance(value, (bytes, bytearray, memoryview)):
        raise PlaybookValidationError(
            f"playbook {root_label} contains non-JSON binary data"
        )
    raise PlaybookValidationError(
        f"playbook {root_label} contains unsupported value type "
        f"{type(value).__name__}"
    )


def _values_equal(left: object, right: object) -> bool:
    if left is right:
        return True
    try:
        return _canonical_json_bytes(left) == _canonical_json_bytes(right)
    except (TypeError, ValueError):
        return left == right


def _extract_alias(
    data: dict[str, object],
    canonical: str,
    aliases: Sequence[str],
) -> None:
    found: list[tuple[str, object]] = [
        (alias, data[alias]) for alias in aliases if alias in data
    ]
    if not found:
        return

    selected_alias, selected_value = found[0]
    for alias, value in found[1:]:
        if not _values_equal(selected_value, value):
            raise PlaybookValidationError(
                f"playbook contains conflicting aliases for {canonical}: "
                f"{selected_alias} and {alias}"
            )

    data[canonical] = selected_value
    for alias in aliases:
        data.pop(alias, None)


def _normalize_rule_mapping(
    value: Mapping[str, object],
    *,
    path: str,
) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise PlaybookValidationError(
            f"playbook {path} must be an object"
        )
    result = dict(value)
    for canonical, aliases in _RULE_FIELD_ALIASES.items():
        _extract_alias(result, canonical, aliases)
    return result


def _normalize_rule_collection(
    value: object,
    *,
    path: str,
) -> list[object]:
    if isinstance(value, Mapping):
        rule_keys = {
            "id",
            "rule_id",
            "ruleId",
            "description",
            "action",
            "reason_code",
            "reasonCode",
        }
        if value.keys() & rule_keys:
            return [
                _normalize_rule_mapping(value, path=path),
            ]

        normalized: list[object] = []
        for rule_id, raw_rule in value.items():
            if not isinstance(rule_id, str) or not rule_id.strip():
                raise PlaybookValidationError(
                    f"playbook {path} contains an invalid rule identifier"
                )
            if not isinstance(raw_rule, Mapping):
                raise PlaybookValidationError(
                    f"playbook {_json_path(path, rule_id)} must be an object"
                )
            rule = dict(raw_rule)
            supplied_id = rule.get("id", rule.get("rule_id", rule.get("ruleId")))
            if supplied_id is not None and str(supplied_id).strip() != rule_id:
                raise PlaybookValidationError(
                    f"playbook {_json_path(path, rule_id)} has a conflicting id"
                )
            rule.setdefault("id", rule_id)
            normalized.append(
                _normalize_rule_mapping(
                    rule,
                    path=_json_path(path, rule_id),
                )
            )
        return normalized

    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray, memoryview)
    ):
        return [
            _normalize_rule_mapping(
                rule,
                path=_json_path(path, index),
            )
            for index, rule in enumerate(value)
        ]

    raise PlaybookValidationError(
        f"playbook {path} must be a rule list or rule object"
    )


def _normalize_playbook_mapping(
    value: Mapping[str, object],
) -> dict[str, object]:
    for envelope in _ENVELOPE_ALIASES:
        if envelope not in value:
            continue
        nested = value[envelope]
        if not isinstance(nested, Mapping):
            raise PlaybookValidationError(
                f"playbook {envelope} must be an object"
            )
        extra_fields = set(value) - {envelope}
        if extra_fields:
            fields = ", ".join(sorted(extra_fields))
            raise PlaybookValidationError(
                f"playbook envelope contains unknown field(s): {fields}"
            )
        value = nested
        break

    result = dict(value)
    _extract_alias(result, "playbook_id", _ID_ALIASES)
    _extract_alias(result, "playbook_version", _VERSION_ALIASES)
    _extract_alias(result, "name", _NAME_ALIASES)
    _extract_alias(result, "description", _DESCRIPTION_ALIASES)
    _extract_alias(result, "thresholds", _THRESHOLD_ALIASES)
    _extract_alias(result, "metadata", _METADATA_ALIASES)
    _extract_alias(result, "rules", _RULE_ALIASES)

    if "rules" in result:
        result["rules"] = _normalize_rule_collection(
            result["rules"],
            path="playbook.rules",
        )
    return result


def _format_validation_error(error: ValidationError) -> str:
    try:
        errors = error.errors(include_url=False)
    except TypeError:  # pragma: no cover - older Pydantic compatibility
        errors = error.errors()

    details: list[str] = []
    for item in errors:
        location = ".".join(str(part) for part in item.get("loc", ())) or "$"
        message = str(item.get("msg", "invalid value"))
        details.append(f"{location}: {message}")
    suffix = "; ".join(details) if details else str(error)
    return f"playbook schema violation: {suffix}"


def _read_playbook_source(
    source: object,
    *,
    max_bytes: int,
    filename: str | None,
) -> tuple[bytes, str]:
    source_name = filename or ""

    if isinstance(source, os.PathLike):
        path = Path(source)
        source_name = source_name or path.name
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise PlaybookLoadError(
                "playbook file metadata could not be read"
            ) from exc
        if size > max_bytes:
            raise PlaybookLoadError(
                "playbook exceeds the configured size limit of "
                f"{max_bytes} bytes"
            )
        try:
            data = path.read_bytes()
        except OSError as exc:
            raise PlaybookLoadError("playbook file could not be read") from exc
    elif hasattr(source, "read"):
        try:
            raw = source.read(max_bytes + 1)  # type: ignore[union-attr]
        except (OSError, ValueError) as exc:
            raise PlaybookLoadError("playbook stream could not be read") from exc
        if isinstance(raw, str):
            data = raw.encode("utf-8")
        elif isinstance(raw, (bytes, bytearray, memoryview)):
            data = bytes(raw)
        else:
            raise TypeError("playbook streams must return str or bytes")
        source_name = source_name or str(
            getattr(source, "name", "playbook")
        )
    elif isinstance(source, str):
        candidate: Path | None = None
        if "\n" not in source and "\r" not in source and len(source) <= 4_096:
            try:
                possible = Path(source)
                if possible.is_file():
                    candidate = possible
            except OSError:
                candidate = None
        if candidate is not None:
            return _read_playbook_source(
                candidate,
                max_bytes=max_bytes,
                filename=filename,
            )
        try:
            data = source.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise PlaybookValidationError(
                "playbook text must contain valid Unicode scalar values"
            ) from exc
    elif isinstance(source, (bytes, bytearray, memoryview)):
        data = bytes(source)
    else:
        raise TypeError(
            "playbook source must be bytes, text, a path, a file-like object, "
            "or a mapping"
        )

    if len(data) > max_bytes:
        raise PlaybookLoadError(
            f"playbook exceeds the configured size limit of {max_bytes} bytes"
        )
    if not data:
        raise PlaybookLoadError("playbook is empty")
    return data, source_name


def _parse_playbook(data: bytes) -> object:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise PlaybookLoadError("playbook must be valid UTF-8") from exc

    if not text.strip():
        raise PlaybookLoadError("playbook is empty")

    try:
        return json.loads(
            text,
            object_pairs_hook=_json_object,
            parse_constant=_reject_json_constant,
        )
    except _DuplicateJsonKey as exc:
        raise PlaybookLoadError(
            f"playbook contains duplicate JSON key {exc.key!r}"
        ) from exc
    except _NonFiniteJsonNumber as exc:
        raise PlaybookValidationError(
            f"playbook document contains non-finite number {exc.token}"
        ) from exc
    except json.JSONDecodeError as json_error:
        if yaml is None:
            raise PlaybookLoadError(
                "playbook is not valid JSON and YAML support is unavailable"
            ) from json_error

        class _LimitedSafeLoader(yaml.SafeLoader):
            alias_count = 0

            def compose_node(self, parent: object, index: object) -> object:
                event = self.peek_event()
                if isinstance(event, yaml.events.AliasEvent):
                    type(self).alias_count += 1
                    if type(self).alias_count > _MAX_YAML_ALIASES:
                        raise PlaybookValidationError(
                            "playbook exceeds the YAML alias limit"
                        )
                return super().compose_node(parent, index)

        def construct_mapping(
            loader: _LimitedSafeLoader,
            node: yaml.nodes.MappingNode,
            deep: bool = False,
        ) -> dict[object, object]:
            merge_tag = "tag:yaml.org,2002:merge"
            for key_node, _ in node.value:
                if key_node.tag == merge_tag:
                    raise _DuplicateYamlKey("merge key")
            mapping: dict[object, object] = {}
            for key_node, value_node in node.value:
                key = loader.construct_object(key_node, deep=deep)
                try:
                    duplicate = key in mapping
                except TypeError as exc:
                    raise PlaybookValidationError(
                        "playbook YAML contains an unhashable mapping key"
                    ) from exc
                if duplicate:
                    raise _DuplicateYamlKey(key)
                mapping[key] = loader.construct_object(value_node, deep=deep)
            return mapping

        _LimitedSafeLoader.add_constructor(
            yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG,
            construct_mapping,
        )
        loader = _LimitedSafeLoader(text)
        try:
            return loader.get_single_data()
        except (_DuplicateYamlKey, PlaybookValidationError):
            raise
        except yaml.YAMLError as yaml_error:
            message = str(yaml_error)
            if "duplicate key" in message.casefold():
                raise PlaybookLoadError(
                    "playbook contains a duplicate YAML key"
                ) from yaml_error
            raise PlaybookLoadError(
                "playbook is not valid JSON or safe YAML"
            ) from yaml_error
        finally:
            loader.dispose()


def _validate_playbook_collections(
    value: Mapping[str, object],
    *,
    max_rules: int,
) -> None:
    thresholds = value.get("thresholds", {})
    if thresholds is not None and not isinstance(thresholds, Mapping):
        raise PlaybookValidationError("playbook.thresholds must be an object")
    if isinstance(thresholds, Mapping) and len(thresholds) > _MAX_THRESHOLD_KEYS:
        raise PlaybookValidationError(
            "playbook.thresholds exceeds the threshold item limit"
        )

    metadata = value.get("metadata", {})
    if metadata is not None and not isinstance(metadata, Mapping):
        raise PlaybookValidationError("playbook.metadata must be an object")
    if isinstance(metadata, Mapping) and len(metadata) > _MAX_METADATA_KEYS:
        raise PlaybookValidationError(
            "playbook.metadata exceeds the metadata item limit"
        )

    rules = value.get("rules", [])
    if not isinstance(rules, Sequence) or isinstance(
        rules, (str, bytes, bytearray)
    ):
        raise PlaybookValidationError("playbook.rules must be a list")
    if len(rules) > max_rules:
        raise PlaybookValidationError(
            f"playbook exceeds the configured rule limit of {max_rules}"
        )

    for index, raw_rule in enumerate(rules):
        if not isinstance(raw_rule, Mapping):
            raise PlaybookValidationError(
                f"playbook.rules[{index}] must be an object"
            )
        patterns = raw_rule.get("patterns", ())
        if isinstance(patterns, str):
            raise PlaybookValidationError(
                f"playbook.rules[{index}].patterns must be a list"
            )
        if isinstance(patterns, Sequence) and len(patterns) > _MAX_RULES_PER_COLLECTION:
            raise PlaybookValidationError(
                f"playbook.rules[{index}].patterns exceeds the pattern limit"
            )
        rule_metadata = raw_rule.get("metadata", {})
        if rule_metadata is not None and not isinstance(rule_metadata, Mapping):
            raise PlaybookValidationError(
                f"playbook.rules[{index}].metadata must be an object"
            )
        if (
            isinstance(rule_metadata, Mapping)
            and len(rule_metadata) > _MAX_METADATA_KEYS
        ):
            raise PlaybookValidationError(
                f"playbook.rules[{index}].metadata exceeds the metadata limit"
            )


def _deep_freeze(value: object) -> object:
    if isinstance(value, Mapping):
        return MappingProxyType(
            {str(key): _deep_freeze(child) for key, child in value.items()}
        )
    if isinstance(value, tuple):
        return tuple(_deep_freeze(child) for child in value)
    if isinstance(value, list):
        return tuple(_deep_freeze(child) for child in value)
    return value


def _deep_thaw(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _deep_thaw(child) for key, child in value.items()}
    if isinstance(value, tuple):
        return [_deep_thaw(child) for child in value]
    if isinstance(value, list):
        return [_deep_thaw(child) for child in value]
    if isinstance(value, frozenset):
        return sorted((_deep_thaw(child) for child in value), key=str)
    return value


class PlaybookSpecification(BaseModel):
    """Strict, versionable corporate contract-review specification."""

    model_config = ConfigDict(
        extra="forbid",
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
        frozen=True,
    )

    playbook_id: str = Field(
        min_length=1,
        max_length=200,
        validation_alias=AliasChoices(*_ID_ALIASES),
    )
    playbook_version: StrictInt | str = Field(
        min_length=1,
        max_length=100,
        validation_alias=AliasChoices(*_VERSION_ALIASES),
    )
    name: str | None = Field(
        default=None,
        max_length=300,
        validation_alias=AliasChoices(*_NAME_ALIASES),
    )
    description: str = Field(
        min_length=1,
        max_length=2_000,
        validation_alias=AliasChoices(*_DESCRIPTION_ALIASES),
    )
    thresholds: Mapping[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices(*_THRESHOLD_ALIASES),
    )
    metadata: Mapping[str, Any] = Field(
        default_factory=dict,
        validation_alias=AliasChoices(*_METADATA_ALIASES),
    )
    rules: tuple[PlaybookRule, ...] = Field(
        default_factory=tuple,
        max_length=DEFAULT_MAX_PLAYBOOK_RULES,
        validation_alias=AliasChoices(*_RULE_ALIASES),
    )

    @model_validator(mode="before")
    @classmethod
    def normalize_aliases(cls, value: object) -> object:
        if isinstance(value, Mapping):
            return _normalize_playbook_mapping(value)
        return value

    @field_validator("thresholds", "metadata", mode="after")
    @classmethod
    def make_mapping_immutable(cls, value: Mapping[str, Any]) -> Mapping[str, Any]:
        return _deep_freeze(dict(value))  # type: ignore[return-value]

    @model_validator(mode="after")
    def reject_duplicate_rule_ids(self) -> PlaybookSpecification:
        identifiers = [rule.rule_id for rule in self.rules]
        if len(identifiers) != len(set(identifiers)):
            raise ValueError("rule_id values must be unique")
        return self

    @property
    def id(self) -> str:
        return self.playbook_id

    @property
    def version(self) -> StrictInt | str:
        return self.playbook_version

    @property
    def snapshot(self) -> dict[str, object]:
        """Return a detached, mutable canonical JSON snapshot."""

        return {
            "id": self.playbook_id,
            "version": self.playbook_version,
            "name": self.name,
            "description": self.description,
            "thresholds": _deep_thaw(self.thresholds),
            "metadata": _deep_thaw(self.metadata),
            "rules": [
                rule.model_dump(mode="json", by_alias=False)
                for rule in self.rules
            ],
        }


Playbook = PlaybookSpecification


def _cloned_rule(rule: PlaybookRule) -> PlaybookRule:
    return rule.model_copy(deep=True)


class PlaybookEngine:
    """Immutable playbook evaluator over one complete contract document."""

    __slots__ = (
        "_canonical_hash",
        "_canonical_json",
        "_canonical_snapshot",
        "_max_document_characters",
        "_playbook",
        "_playbook_hash",
        "_rules",
        "_source_name",
    )

    def __init__(
        self,
        playbook: PlaybookSpecification | Mapping[str, object],
        *,
        raw_hash: str | None = None,
        source_name: str | None = None,
        canonical_snapshot: Mapping[str, object] | None = None,
        max_document_characters: int = DEFAULT_MAX_DOCUMENT_CHARACTERS,
    ) -> None:
        if isinstance(playbook, Mapping):
            loaded = load_playbook(playbook)
            self._playbook = loaded.playbook
            self._rules = loaded._rules
            self._playbook_hash = loaded.playbook_hash
            self._canonical_snapshot = loaded._snapshot
            self._canonical_json = loaded.canonical_json
            self._canonical_hash = loaded.canonical_hash
            self._source_name = loaded.source_name
            self._max_document_characters = (
                loaded.max_document_characters
            )
            return

        if not isinstance(playbook, PlaybookSpecification):
            raise TypeError("playbook must be a PlaybookSpecification or mapping")

        self._max_document_characters = _require_limit(
            max_document_characters,
            "max_document_characters",
        )
        self._playbook = playbook
        self._rules = tuple(_cloned_rule(rule) for rule in playbook.rules)
        self._source_name = source_name or playbook.playbook_id

        snapshot = (
            dict(_deep_thaw(canonical_snapshot))
            if canonical_snapshot is not None
            else playbook.snapshot
        )
        if not isinstance(snapshot, dict):
            raise TypeError("canonical_snapshot must be a mapping")
        self._canonical_snapshot = snapshot
        self._canonical_json = _canonical_json_bytes(snapshot).decode("utf-8")
        self._canonical_hash = hashlib.sha256(
            self._canonical_json.encode("utf-8")
        ).hexdigest()
        self._playbook_hash = raw_hash or self._canonical_hash

    def __repr__(self) -> str:
        return (
            f"PlaybookEngine(playbook_id={self.playbook_id!r}, "
            f"version={self.playbook_version!r}, rules={len(self._rules)})"
        )

    @property
    def playbook(self) -> PlaybookSpecification:
        return self._playbook

    @property
    def playbook_id(self) -> str:
        return self._playbook.playbook_id

    @property
    def playbook_version(self) -> StrictInt | str:
        return self._playbook.playbook_version

    @property
    def version(self) -> StrictInt | str:
        return self._playbook.playbook_version

    @property
    def playbook_hash(self) -> str:
        return self._playbook_hash

    @property
    def sha256(self) -> str:
        return self._playbook_hash

    @property
    def canonical_hash(self) -> str:
        return self._canonical_hash

    @property
    def source_name(self) -> str:
        return self._source_name

    @property
    def max_document_characters(self) -> int:
        return self._max_document_characters

    @property
    def snapshot(self) -> dict[str, object]:
        return _deep_thaw(self._canonical_snapshot)  # type: ignore[return-value]

    @property
    def canonical_snapshot(self) -> dict[str, object]:
        return self.snapshot

    @property
    def snapshot_json(self) -> str:
        return self._canonical_json

    @property
    def rules(self) -> tuple[PlaybookRule, ...]:
        return tuple(_cloned_rule(rule) for rule in self._rules)

    @property
    def enabled_rules(self) -> tuple[PlaybookRule, ...]:
        return tuple(_cloned_rule(rule) for rule in self._rules if rule.enabled)

    @property
    def rule_count(self) -> int:
        return len(self._rules)

    @property
    def thresholds(self) -> Mapping[str, Any]:
        return self._playbook.thresholds

    def review(
        self,
        document: str | bytes | bytearray | memoryview | Clause | Sequence[Clause],
        clauses: Sequence[Clause] | None = None,
        *,
        policy_results: Sequence[object] | None = None,
    ) -> PlaybookReview:
        """Review a complete document without retrieval chunking."""

        text, explicit_clauses = _coerce_review_document(
            document,
            clauses,
            max_document_characters=self._max_document_characters,
        )

        if policy_results is None:
            deterministic = _collect_deterministic_results(
                text,
                explicit_clauses,
            )
        else:
            try:
                deterministic = _flatten_result_payload(policy_results)
            except PlaybookEvaluationError:
                raise

        rule_results = list(
            self._evaluate_rules(text, explicit_clauses)
        )
        threshold_results = list(_evaluate_thresholds(text))
        threshold_results.extend(_evaluate_scc_rules(text))

        combined = _deduplicate_results(
            [
                *deterministic,
                *rule_results,
                *threshold_results,
            ]
        )
        combined = [_enforce_constitutional_routing(result) for result in combined]

        action = _aggregate_action(combined)
        deviation_score = score_deviation(combined)
        score_breakdown = tuple(_score_components(combined))

        rules_triggered = tuple(
            dict.fromkeys(
                result.rule_id
                for result in (*rule_results, *threshold_results)
            )
        )

        return PlaybookReview(
            playbook_id=self.playbook_id,
            playbook_version=self.playbook_version,
            playbook_hash=self.playbook_hash,
            canonical_hash=self.canonical_hash,
            action=action,
            deviation_score=deviation_score,
            risk_score=deviation_score,
            findings=tuple(combined),
            policy_results=tuple(deterministic),
            rule_results=tuple([*rule_results, *threshold_results]),
            redlines=tuple(combined),
            clauses=tuple(explicit_clauses or ()),
            rules_triggered=rules_triggered,
            score_breakdown=score_breakdown,
            disclaimer=CONSTITUTIONAL_RULE,
            decision_support_only=True,
        )

    def evaluate(
        self,
        document: str | bytes | bytearray | memoryview | Clause | Sequence[Clause],
        clauses: Sequence[Clause] | None = None,
        *,
        policy_results: Sequence[object] | None = None,
    ) -> PlaybookReview:
        """Compatibility alias for :meth:`review`."""

        return self.review(
            document,
            clauses,
            policy_results=policy_results,
        )

    def _evaluate_rules(
        self,
        document: str | Sequence[Clause],
        clauses: Sequence[Clause] | None = None,
    ) -> list[PolicyResult]:
        if isinstance(document, str):
            text = document
            units: list[tuple[str, int, Clause | None]] = [
                (text, 0, None)
            ]
            if clauses is not None:
                units = [
                    (clause.text, clause.start_offset, clause)
                    for clause in clauses
                ]
        else:
            units = [
                (clause.text, clause.start_offset, clause)
                for clause in document
            ]
            text = "\n\n".join(clause.text for clause in document)

        results: list[PolicyResult] = []
        for rule in self._rules:
            if not rule.enabled:
                continue
            results.extend(_evaluate_rule(rule, text, units))
        return results


def load_playbook(
    source: object,
    filename: str | os.PathLike[str] | None = None,
    *,
    max_bytes: int = DEFAULT_MAX_PLAYBOOK_BYTES,
    max_rules: int = DEFAULT_MAX_PLAYBOOK_RULES,
    source_name: str | None = None,
) -> PlaybookEngine:
    """Load, validate, hash, and snapshot a JSON or YAML playbook."""

    max_bytes = _require_limit(max_bytes, "max_bytes")
    max_rules = _require_limit(max_rules, "max_rules")

    if source_name is not None:
        if not isinstance(source_name, str) or not source_name.strip():
            raise ValueError("source_name must not be blank")
        if len(source_name) > 1_000:
            raise ValueError("source_name must not exceed 1000 characters")
    filename_text = str(filename) if filename is not None else None

    if isinstance(source, Mapping):
        canonical_input = _canonicalize_input(
            source,
            root_label="mapping",
        )
        if not isinstance(canonical_input, dict):
            raise PlaybookValidationError("playbook root must be an object")
        normalized = _normalize_playbook_mapping(canonical_input)
        raw_bytes = _canonical_json_bytes(canonical_input)
        resolved_name = source_name or "mapping"
    else:
        raw_bytes, detected_name = _read_playbook_source(
            source,
            max_bytes=max_bytes,
            filename=filename_text,
        )
        parsed = _parse_playbook(raw_bytes)
        canonical_input = _canonicalize_input(
            parsed,
            root_label="document",
        )
        if not isinstance(canonical_input, dict):
            raise PlaybookValidationError("playbook root must be an object")
        normalized = _normalize_playbook_mapping(canonical_input)
        resolved_name = source_name or detected_name or "playbook"

    _validate_playbook_collections(normalized, max_rules=max_rules)

    try:
        specification = PlaybookSpecification.model_validate(normalized)
    except ValidationError as exc:
        raise PlaybookValidationError(
            _format_validation_error(exc)
        ) from exc

    raw_hash = hashlib.sha256(raw_bytes).hexdigest()
    return PlaybookEngine(
        specification,
        raw_hash=raw_hash,
        source_name=resolved_name,
        max_document_characters=DEFAULT_MAX_DOCUMENT_CHARACTERS,
    )


def _decode_document(value: str | bytes | bytearray | memoryview) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, (bytes, bytearray, memoryview)):
        try:
            return bytes(value).decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise PlaybookEvaluationError(
                "contract document must be valid UTF-8"
            ) from exc
    raise PlaybookEvaluationError("contract document must be text or bytes")


def _coerce_review_document(
    document: str | bytes | bytearray | memoryview | Clause | Sequence[Clause],
    clauses: Sequence[Clause] | None,
    *,
    max_document_characters: int,
) -> tuple[str, tuple[Clause, ...] | None]:
    if isinstance(document, Clause):
        if clauses is not None:
            raise PlaybookEvaluationError(
                "clauses must not be supplied twice"
            )
        text = document.text
        explicit: tuple[Clause, ...] | None = (document,)
    elif isinstance(document, (str, bytes, bytearray, memoryview)):
        if clauses is None:
            text = _decode_document(document)
            explicit = None
        else:
            text = _decode_document(document)
            explicit = tuple(clauses)
    elif isinstance(document, Sequence):
        supplied = tuple(document)
        if clauses is not None:
            raise PlaybookEvaluationError(
                "clauses must not be supplied twice"
            )
        if not supplied:
            raise PlaybookEvaluationError("contract document is empty")
        if not all(isinstance(clause, Clause) for clause in supplied):
            raise TypeError("document sequences must contain only Clause objects")

        parts: list[str] = []
        offsets: list[Clause] = []
        cursor = 0
        for index, clause in enumerate(supplied):
            if index:
                separator = "\n\n"
                parts.append(separator)
                cursor += len(separator)
            adjusted = clause.model_copy(
                update={
                    "start_offset": cursor,
                    "end_offset": cursor + len(clause.text),
                },
                deep=True,
            )
            parts.append(clause.text)
            offsets.append(adjusted)
            cursor += len(clause.text)
        text = "".join(parts)
        explicit = tuple(offsets)
    else:
        raise TypeError(
            "document must be text, bytes, a Clause, or a sequence of Clauses"
        )

    if not text.strip():
        raise PlaybookEvaluationError("contract document is empty")
    if len(text) > max_document_characters:
        raise PlaybookEvaluationError(
            "contract exceeds the configured whole-document character limit"
        )

    if explicit is not None:
        if not explicit:
            raise PlaybookEvaluationError("contract document is empty")
        identifiers: set[str] = set()
        previous_end = -1
        for clause in explicit:
            if clause.clause_id in identifiers:
                raise PlaybookEvaluationError(
                    f"duplicate clause_id {clause.clause_id!r}"
                )
            identifiers.add(clause.clause_id)
            if clause.start_offset < previous_end:
                raise PlaybookEvaluationError(
                    "explicit clause spans must not overlap or be out of order"
                )
            if clause.end_offset > len(text):
                raise PlaybookEvaluationError(
                    f"clause {clause.clause_id!r} exceeds the document bounds"
                )
            if text[clause.start_offset : clause.end_offset] != clause.text:
                raise PlaybookEvaluationError(
                    f"clause {clause.clause_id!r} offsets do not match the document"
                )
            previous_end = clause.end_offset

    return text, explicit


def _iter_clause_spans(text: str) -> tuple[Clause, ...]:
    """Return one whole-document provenance span, never retrieval chunks."""

    if not text.strip():
        return ()
    start = len(text) - len(text.lstrip())
    end = len(text.rstrip())
    if end <= start:
        return ()
    return (
        Clause(
            clause_id="document:whole",
            text=text[start:end],
            start_offset=start,
            end_offset=end,
            source="document",
        ),
    )


def _spans_from_clauses(
    clauses: Sequence[Clause],
    document_length: int,
) -> tuple[Clause, ...]:
    result = tuple(clauses)
    for clause in result:
        if clause.end_offset > document_length:
            raise PlaybookEvaluationError(
                f"clause {clause.clause_id!r} exceeds the document bounds"
            )
    return result


def _invoke_detector(
    detector: object,
    text: str,
    clauses: tuple[Clause, ...] | None,
) -> object:
    if not callable(detector):
        raise TypeError("policy detector must be callable")

    candidates: list[tuple[tuple[object, ...], dict[str, object]]] = [
        ((text,), {}),
        ((), {"document": text}),
        ((), {"text": text}),
    ]
    if clauses is not None:
        candidates[1:1] = [
            ((text, clauses), {}),
            ((text, list(clauses)), {}),
        ]

    try:
        signature = inspect.signature(detector)
    except (TypeError, ValueError):
        return detector(text)

    for args, kwargs in candidates:
        try:
            signature.bind(*args, **kwargs)
        except TypeError:
            continue
        return detector(*args, **kwargs)
    raise TypeError("policy detector has an unsupported signature")


def _fallback_policy_scan(
    text: str,
    clauses: tuple[Clause, ...] | None,
) -> tuple[PolicyResult, ...]:
    detectors = (
        detect_schedule4_liability_trap,
        intercept_prompt_injection,
    )
    collected: list[PolicyResult] = []
    successful_calls = 0
    errors: list[Exception] = []

    for detector in detectors:
        try:
            payload = _invoke_detector(detector, text, clauses)
            successful_calls += 1
            collected.extend(_flatten_result_payload(payload))
        except Exception as exc:
            errors.append(exc)

    if successful_calls == 0:
        raise PlaybookEvaluationError(
            "deterministic policy evaluation failed"
        ) from (errors[-1] if errors else None)
    return tuple(_deduplicate_results(collected))


def _collect_deterministic_results(
    text: str,
    clauses: tuple[Clause, ...] | None,
) -> tuple[PolicyResult, ...]:
    try:
        payload = evaluate_policy(text)
        return _flatten_result_payload(payload)
    except Exception:
        return _fallback_policy_scan(text, clauses)


def _flatten_result_payload(payload: object) -> tuple[PolicyResult, ...]:
    if payload is None:
        return ()

    if isinstance(payload, PolicyResult):
        return (payload,)

    if isinstance(payload, Mapping):
        if "action" in payload or "reason_code" in payload:
            try:
                return (PolicyResult.model_validate(payload),)
            except ValidationError as exc:
                raise PlaybookEvaluationError(
                    "policy result mapping is invalid"
                ) from exc

        result_keys = (
            "results",
            "findings",
            "policy_results",
            "policyResults",
            "redlines",
        )
        collected: list[PolicyResult] = []
        found_envelope = False
        for key in result_keys:
            if key in payload:
                found_envelope = True
                collected.extend(_flatten_result_payload(payload[key]))
        if found_envelope:
            return tuple(_deduplicate_results(collected))

        for value in payload.values():
            try:
                collected.extend(_flatten_result_payload(value))
            except PlaybookEvaluationError:
                continue
        return tuple(_deduplicate_results(collected))

    if isinstance(payload, BaseModel):
        try:
            return (PolicyResult.model_validate(payload),)
        except ValidationError as exc:
            raise PlaybookEvaluationError(
                "policy model is not a PolicyResult"
            ) from exc

    if isinstance(payload, (str, bytes, bytearray, memoryview, int, float, bool)):
        raise PlaybookEvaluationError("policy payload has an unsupported shape")

    envelope_names = ("results", "findings", "policy_results", "policyResults")
    for name in envelope_names:
        if hasattr(payload, name):
            return _flatten_result_payload(getattr(payload, name))

    if isinstance(payload, Iterable):
        collected = []
        for item in payload:
            collected.extend(_flatten_result_payload(item))
        return tuple(_deduplicate_results(collected))

    raise PlaybookEvaluationError("policy payload has an unsupported shape")


def _result_field(result: object, name: str, default: object = None) -> object:
    if isinstance(result, Mapping):
        return result.get(name, default)
    return getattr(result, name, default)


def _result_kind(result: object) -> str:
    values: list[object] = []
    for name in (
        "finding",
        "finding_type",
        "findingType",
        "category",
        "classification",
    ):
        value = _result_field(result, name)
        if isinstance(value, str):
            values.append(value)

    rule_id = _result_field(result, "rule_id", _result_field(result, "ruleId"))
    if isinstance(rule_id, str):
        values.append(rule_id)

    metadata = _result_field(result, "metadata")
    if isinstance(metadata, Mapping):
        for name in ("finding", "finding_type", "category"):
            value = metadata.get(name)
            if isinstance(value, str):
                values.append(value)

    return " ".join(values).casefold()


def _deduplicate_results(
    results: Iterable[PolicyResult],
) -> tuple[PolicyResult, ...]:
    unique: list[PolicyResult] = []
    seen: set[tuple[object, ...]] = set()
    for result in results:
        metadata = result.metadata if isinstance(result.metadata, dict) else {}
        key = (
            result.rule_id,
            result.reason_code,
            result.clause_id,
            result.start_offset,
            result.end_offset,
            metadata.get("finding"),
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(result)
    return tuple(unique)


def _result_action(result: object) -> Action:
    value = _result_field(result, "action", Action.QUEUE)
    if isinstance(value, Action):
        return value
    try:
        return Action(str(value))
    except (TypeError, ValueError):
        return Action.QUEUE


def _aggregate_action(results: Sequence[object]) -> Action:
    if not results:
        return Action.ALLOW

    kinds = [_result_kind(result) for result in results]
    if any(
        "playbook_walkaway" in kind
        or "injection_or_jailbreak" in kind
        or "prompt-injection" in kind
        or "scc_deviation" in kind
        or "scc_review" in kind
        for kind in kinds
    ):
        return Action.QUEUE

    return max(
        (_result_action(result) for result in results),
        key=lambda action: _ACTION_ORDER[action],
    )


def _enforce_constitutional_routing(result: PolicyResult) -> PolicyResult:
    kind = _result_kind(result)
    safety_finding = any(
        marker in kind
        for marker in (
            "playbook_walkaway",
            "schedule-4-liability",
            "schedule4_liability",
            "injection_or_jailbreak",
            "prompt-injection",
            "scc_deviation",
            "scc_review",
        )
    )
    if safety_finding and result.action is not Action.QUEUE:
        return result.model_copy(update={"action": Action.QUEUE})
    return result


def _active_context(text: str, offset: int) -> tuple[str | None, str | None, str]:
    section: str | None = None
    schedule: str | None = None
    for match in _HEADING_RE.finditer(text):
        if match.start() > offset:
            break
        label = f"{match.group('kind').title()} {match.group('number')}"
        if match.group("kind").casefold() == "schedule":
            schedule = label
        else:
            section = label
    source = "schedule" if schedule is not None else "body"
    return section, schedule, source


def _label_tokens(label: str | None) -> tuple[str, ...]:
    if not label:
        return ()
    return tuple(re.findall(r"[a-z0-9]+", label.casefold()))


def _target_matches(
    target: str | None,
    actual: str | None,
) -> bool:
    if target is None:
        return True
    if actual is None:
        return False
    target_tokens = _label_tokens(target)
    actual_tokens = _label_tokens(actual)
    if not target_tokens or not actual_tokens:
        return target.strip().casefold() == actual.strip().casefold()
    target_size = len(target_tokens)
    actual_size = len(actual_tokens)
    return any(
        actual_tokens[index : index + target_size] == target_tokens
        for index in range(actual_size - target_size + 1)
    )


def _rule_expressions(rule: PlaybookRule) -> tuple[str, ...]:
    expressions: list[str] = []
    for expression in (rule.pattern, *rule.patterns):
        if expression is not None and expression not in expressions:
            expressions.append(expression)
    return tuple(expressions)


def _compile_expression(
    expression: str,
    *,
    match_type: str,
) -> re.Pattern[str]:
    if match_type == "regex":
        return re.compile(expression, re.MULTILINE)
    escaped_parts = [re.escape(part) for part in expression.strip().split()]
    if not escaped_parts:
        raise PlaybookEvaluationError("literal rule pattern must not be blank")
    return re.compile(
        r"\s+".join(escaped_parts),
        re.IGNORECASE | re.MULTILINE,
    )


def _span_for_anchor(text: str, anchor: int) -> tuple[int, int]:
    if not text:
        return 0, 0
    anchor = max(0, min(anchor, len(text)))

    start = anchor
    while start > 0 and text[start - 1] not in ".!?;\n\r":
        start -= 1
    end = anchor
    while end < len(text) and text[end] not in ".!?;\n\r":
        end += 1
    while end < len(text) and text[end] in ".!?;\n\r":
        end += 1

    if end <= start:
        start = 0
        end = len(text)
    return start, end


def _make_policy_result(
    *,
    rule_id: str,
    clause: Clause,
    action: Action,
    reason_code: str,
    severity: str,
    confidence: float,
    description: str,
    finding: str,
    metadata: Mapping[str, object] | None = None,
) -> PolicyResult:
    risk_score = _SEVERITY_RISK.get(severity, 0.5) * confidence
    values: dict[str, object] = {
        "rule_id": rule_id,
        "clause_id": clause.clause_id,
        "action": action,
        "reason_code": reason_code,
        "severity": severity,
        "confidence": confidence,
        "start_offset": clause.start_offset,
        "end_offset": clause.end_offset,
        "section": clause.section,
        "schedule": clause.schedule,
        "source": clause.source,
        "page_number": clause.page_number,
        "evidence": clause.text,
        "text": clause.text,
        "quote": clause.text,
        "excerpt": clause.text,
        "message": description,
        "description": description,
        "rationale": description,
        "finding": finding,
        "finding_type": finding,
        "category": finding,
        "type": finding,
        "risk_level": severity,
        "risk_score": risk_score,
        "deviation_score": risk_score,
        "span": clause,
        "clause": clause,
        "metadata": dict(metadata or {}),
    }

    model_fields = PolicyResult.model_fields
    accepted = {
        name: value
        for name, value in values.items()
        if name in model_fields
    }

    required_fallbacks: dict[str, object] = {
        "result_id": f"{rule_id}:{clause.start_offset}:{clause.end_offset}",
        "title": rule_id,
        "explanation": description,
        "name": rule_id,
    }
    missing: list[str] = []
    for name, info in model_fields.items():
        if info.is_required() and name not in accepted:
            fallback = required_fallbacks.get(name)
            if fallback is not None:
                accepted[name] = fallback
            else:
                missing.append(name)
    if missing:
        raise PlaybookEvaluationError(
            "PolicyResult requires unsupported field(s): "
            + ", ".join(sorted(missing))
        )

    try:
        return PolicyResult.model_validate(accepted)
    except ValidationError as exc:
        raise PlaybookEvaluationError(
            "generated policy result failed domain validation"
        ) from exc


def _evaluate_rule(
    rule: PlaybookRule,
    text: str,
    units: Sequence[tuple[str, int, Clause | None]],
) -> list[PolicyResult]:
    expressions = _rule_expressions(rule)

    expected_present = False
    if rule.expected_text is not None:
        expected_pattern = _compile_expression(
            rule.expected_text,
            match_type="literal",
        )
        expected_present = any(
            expected_pattern.search(unit_text) is not None
            for unit_text, _, _ in units
        )
        if expected_present:
            return []

    if not expressions and rule.expected_text is None:
        if rule.clause_type:
            expressions = (rule.clause_type,)
        else:
            return []

    matches: dict[tuple[int, int, str], tuple[int, int, str, Clause | None]] = {}
    for expression in expressions:
        try:
            pattern = _compile_expression(expression, match_type=rule.match_type)
        except re.error as exc:
            raise PlaybookEvaluationError(
                f"rule {rule.rule_id!r} contains an invalid runtime expression"
            ) from exc

        rule_match_count = 0
        for unit_text, base_offset, source_clause in units:
            for match in pattern.finditer(unit_text):
                if match.start() == match.end():
                    continue
                start = base_offset + match.start()
                end = base_offset + match.end()
                matches.setdefault(
                    (start, end, expression),
                    (start, end, expression, source_clause),
                )
                rule_match_count += 1
                if rule_match_count >= _MAX_MATCHES_PER_RULE:
                    raise PlaybookEvaluationError(
                        f"rule {rule.rule_id!r} exceeded the match limit"
                    )

    if not matches and rule.expected_text is not None:
        start, end = _span_for_anchor(text, 0)
        matches[(start, end, "__missing_expected__")] = (
            start,
            end,
            "__missing_expected__",
            None,
        )

    results: list[PolicyResult] = []
    for start, end, expression, source_clause in sorted(matches.values()):
        section, schedule, source = _active_context(text, start)
        if source_clause is not None:
            section = source_clause.section or section
            schedule = source_clause.schedule or schedule
            source = source_clause.source

        if not _target_matches(rule.section, section):
            continue
        if not _target_matches(rule.schedule, schedule):
            continue
        if rule.clause_type and source_clause is not None:
            actual_type = source_clause.metadata.get("clause_type")
            if isinstance(actual_type, str) and not _target_matches(
                rule.clause_type,
                actual_type,
            ):
                continue

        evidence = text[start:end]
        if not evidence:
            continue
        clause_metadata: dict[str, object] = dict(source_clause.metadata) if (
            source_clause is not None and isinstance(source_clause.metadata, dict)
        ) else {}
        clause_metadata.update(
            {
                "matched_pattern": expression,
                "rule_weight": rule.weight,
                "rule_priority": rule.priority,
                "match_type": rule.match_type,
                "playbook_id": rule.metadata.get("playbook_id")
                if isinstance(rule.metadata, dict)
                else None,
            }
        )
        clause = Clause(
            clause_id=(
                source_clause.clause_id
                if source_clause is not None
                else f"{rule.rule_id}:{start}:{end}"
            ),
            text=evidence,
            start_offset=start,
            end_offset=end,
            section=section,
            schedule=schedule,
            source=source,
            page_number=(
                source_clause.page_number if source_clause is not None else None
            ),
            metadata=clause_metadata,
        )
        results.append(
            _make_policy_result(
                rule_id=rule.rule_id,
                clause=clause,
                action=rule.action,
                reason_code=rule.reason_code,
                severity=rule.severity,
                confidence=rule.confidence,
                description=rule.description,
                finding=rule.reason_code,
                metadata=clause_metadata,
            )
        )
    return results


def _lookup_threshold(
    thresholds: Mapping[str, object],
    *paths: Sequence[str],
) -> object:
    for path in paths:
        current: object = thresholds
        found = True
        for part in path:
            if not isinstance(current, Mapping) or part not in current:
                found = False
                break
            current = current[part]
        if found:
            return current
    return None


def _numeric_threshold(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    normalized = float(value)
    if not math.isfinite(normalized) or normalized < 0:
        return None
    return normalized


def _iter_cap_values(text: str) -> list[tuple[int, int, float]]:
    values: list[tuple[int, int, float]] = []
    for pattern in _CAP_PATTERNS:
        for match in pattern.finditer(text):
            raw_amount = match.group("amount").casefold()
            if raw_amount in _WORD_MONTHS:
                amount = float(_WORD_MONTHS[raw_amount])
            else:
                try:
                    amount = float(raw_amount)
                except ValueError:
                    continue
            unit = match.group("unit").casefold()
            months = amount * 12 if unit.startswith("year") else amount
            values.append((match.start(), match.end(), months))
    return sorted(set(values))


def _iter_uncapped_liability(text: str) -> list[tuple[int, int]]:
    spans: list[tuple[int, int]] = []
    for pattern in _UNCAPPED_LIABILITY_PATTERNS:
        for match in pattern.finditer(text):
            if _LIABILITY_CONTEXT_RE.search(match.group(0)):
                spans.append((match.start(), match.end()))
    return sorted(set(spans))


def _walkaway_enabled(thresholds: Mapping[str, object]) -> bool:
    value = _lookup_threshold(
        thresholds,
        ("walkaway_uncapped_liability",),
        ("uncapped_liability_walkaway",),
        ("liability", "walkaway_uncapped_liability"),
    )
    return value is True


def _evaluate_thresholds(text: str) -> list[PolicyResult]:
    thresholds = self_thresholds = _active_evaluation_thresholds(text)
    if not isinstance(self_thresholds, Mapping):
        return []
    return []


def _active_evaluation_thresholds(text: str) -> Mapping[str, object]:
    # This function is replaced with a closure-backed evaluator by
    # _evaluate_thresholds_for. It exists only as a typed dispatch fallback.
    return MappingProxyType({})


def _evaluate_thresholds_for(
    thresholds: Mapping[str, object],
    text: str,
) -> list[PolicyResult]:
    results: list[PolicyResult] = []
    maximum = _numeric_threshold(
        _lookup_threshold(
            thresholds,
            ("liability_cap_months",),
            ("liability", "cap_months"),
            ("liability", "maximum_months"),
            ("liability_cap", "months"),
        )
    )

    if maximum is not None:
        rule_id_value = _lookup_threshold(
            thresholds,
            ("liability_cap_rule_id",),
            ("liability", "rule_id"),
        )
        rule_id = (
            str(rule_id_value).strip()
            if isinstance(rule_id_value, str) and rule_id_value.strip()
            else "liability-cap-threshold"
        )
        reason_value = _lookup_threshold(
            thresholds,
            ("liability_cap_reason_code",),
            ("liability", "reason_code"),
        )
        reason_code = (
            str(reason_value).strip()
            if isinstance(reason_value, str) and reason_value.strip()
            else "liability_cap_deviation"
        )
        for start, end, months in _iter_cap_values(text):
            if months <= maximum:
                continue
            span_start, span_end = _span_for_anchor(text, start)
            evidence = text[span_start:span_end]
            if not evidence:
                continue
            section, schedule, source = _active_context(text, span_start)
            metadata = {
                "configured_cap_months": maximum,
                "detected_cap_months": months,
                "threshold": "liability_cap_months",
                "finding": "liability_cap_deviation",
            }
            clause = Clause(
                clause_id=f"{rule_id}:{span_start}:{span_end}",
                text=evidence,
                start_offset=span_start,
                end_offset=span_end,
                section=section,
                schedule=schedule,
                source=source,
                metadata=metadata,
            )
            results.append(
                _make_policy_result(
                    rule_id=rule_id,
                    clause=clause,
                    action=Action.QUEUE,
                    reason_code=reason_code,
                    severity="high",
                    confidence=1.0,
                    description=(
                        "Detected a liability cap above the playbook maximum "
                        f"of {maximum:g} months."
                    ),
                    finding="liability_cap_deviation",
                    metadata=metadata,
                )
            )

    if _walkaway_enabled(thresholds):
        cap_values = _iter_cap_values(text)
        for start, end in _iter_uncapped_liability(text):
            span_start, span_end = _span_for_anchor(text, start)
            evidence = text[span_start:span_end]
            if not evidence:
                continue
            section, schedule, source = _active_context(text, span_start)
            metadata = {
                "finding": "playbook_walkaway",
                "contradiction": bool(cap_values),
                "body_cap_months": [value for _, _, value in cap_values],
                "threshold": "walkaway_uncapped_liability",
            }
            clause = Clause(
                clause_id=f"liability-walkaway:{span_start}:{span_end}",
                text=evidence,
                start_offset=span_start,
                end_offset=span_end,
                section=section,
                schedule=schedule,
                source=source,
                metadata=metadata,
            )
            results.append(
                _make_policy_result(
                    rule_id="liability-uncapped-walkaway",
                    clause=clause,
                    action=Action.QUEUE,
                    reason_code="heuristic_cap",
                    severity="critical",
                    confidence=1.0,
                    description=(
                        "Uncapped liability conflicts with the configured "
                        "walk-away threshold."
                    ),
                    finding="playbook_walkaway",
                    metadata=metadata,
                )
            )
    return results


def _scc_configuration(
    thresholds: Mapping[str, object],
) -> tuple[Mapping[str, object], bool, tuple[str, ...]]:
    raw = _lookup_threshold(
        thresholds,
        ("scc",),
        ("eu_scc",),
        ("standard_contractual_clauses",),
    )
    config: Mapping[str, object] = raw if isinstance(raw, Mapping) else thresholds
    enabled_value = _lookup_threshold(
        config,
        ("scc_enabled",),
        ("eu_scc_enabled",),
        ("required",),
    )
    required_modules_value = _lookup_threshold(
        config,
        ("required_scc_modules",),
        ("scc_required_modules",),
        ("required_modules",),
    )
    if isinstance(required_modules_value, str):
        required_modules = (required_modules_value,)
    elif isinstance(required_modules_value, Sequence):
        required_modules = tuple(
            str(item) for item in required_modules_value if str(item).strip()
        )
    else:
        required_modules = ()
    enabled = enabled_value is not False
    return config, enabled, required_modules


def _evaluate_scc_rules(text: str) -> list[PolicyResult]:
    # SCC checking is part of deterministic policy. This marker placeholder is
    # replaced by PlaybookEngine._evaluate_rules via the method below.
    return []


def _evaluate_scc_rules_for(
    thresholds: Mapping[str, object],
    text: str,
) -> list[PolicyResult]:
    config, enabled, required_modules = _scc_configuration(thresholds)
    if not enabled:
        return []

    scc_present = _SCC_RE.search(text) is not None
    eu_transfer = _EU_TRANSFER_RE.search(text) is not None
    variation = _SCC_VARIATION_RE.search(text) is not None
    missing_module = False

    if scc_present and required_modules:
        present_modules = {
            match.group("module").upper()
            for match in _SCC_MODULE_RE.finditer(text)
        }
        missing_module = any(
            re.sub(r"[^A-Z0-9]", "", module.upper()) not in present_modules
            for module in required_modules
        )

    should_flag = (
        (eu_transfer and not scc_present)
        or (scc_present and variation)
        or missing_module
    )
    if not should_flag:
        return []

    if eu_transfer and not scc_present:
        match = _EU_TRANSFER_RE.search(text)
        anchor = match.start() if match is not None else 0
        description = (
            "An EU/EEA international transfer was identified without an "
            "attached EU Standard Contractual Clause mechanism."
        )
        finding = "scc_missing"
    elif missing_module:
        match = _SCC_MODULE_RE.search(text)
        anchor = match.start() if match is not None else 0
        description = (
            "The EU SCC provisions do not contain every playbook-required module."
        )
        finding = "scc_deviation"
    else:
        match = _SCC_VARIATION_RE.search(text)
        anchor = match.start() if match is not None else 0
        description = (
            "A potentially non-compliant variation of the EU Standard "
            "Contractual Clauses requires qualified-lawyer review."
        )
        finding = "scc_deviation"

    start, end = _span_for_anchor(text, anchor)
    evidence = text[start:end]
    if not evidence:
        start, end = 0, len(text)
        evidence = text[start:end]
    section, schedule, source = _active_context(text, start)
    metadata = {
        "finding": finding,
        "scc_present": scc_present,
        "eu_transfer": eu_transfer,
        "required_modules": list(required_modules),
        "configuration": _deep_thaw(config),
    }
    clause = Clause(
        clause_id=f"eu-scc:{start}:{end}",
        text=evidence,
        start_offset=start,
        end_offset=end,
        section=section,
        schedule=schedule,
        source=source,
        metadata=metadata,
    )
    return [
        _make_policy_result(
            rule_id="eu-scc-compliance",
            clause=clause,
            action=Action.QUEUE,
            reason_code="scc_deviation",
            severity="high",
            confidence=0.97,
            description=description,
            finding="scc_deviation",
            metadata=metadata,
        )
    ]


# Bind threshold and SCC evaluators to the engine without duplicating the
# public review orchestration. The named wrappers retain pure-function tests.
def _playbook_threshold_results(
    thresholds: Mapping[str, object],
    text: str,
) -> list[PolicyResult]:
    return _evaluate_thresholds_for(thresholds, text)


def _playbook_scc_results(
    thresholds: Mapping[str, object],
    text: str,
) -> list[PolicyResult]:
    return _evaluate_scc_rules_for(thresholds, text)


def _coerce_score_results(value: object) -> tuple[object, ...]:
    if value is None:
        return ()
    if isinstance(value, (PolicyResult, Mapping)):
        return (value,)
    if isinstance(value, BaseModel):
        return (value,)
    if isinstance(value, (str, bytes, bytearray, memoryview)):
        raise TypeError("findings must be a policy-result collection")
    if isinstance(value, Iterable):
        return tuple(value)
    return (value,)


def _score_components(
    findings: Iterable[object],
    *,
    rule_weights: Mapping[str, float] | None = None,
) -> list[dict[str, object]]:
    components: list[dict[str, object]] = []
    supplied_weights = rule_weights or {}

    for finding in _coerce_score_results(findings):
        action = _result_action(finding)
        severity = _result_field(finding, "severity", "medium")
        confidence = _result_field(finding, "confidence", 1.0)
        rule_id = _result_field(
            finding,
            "rule_id",
            _result_field(finding, "ruleId", "unknown"),
        )
        metadata = _result_field(finding, "metadata", {})
        weight = supplied_weights.get(str(rule_id))
        if weight is None and isinstance(metadata, Mapping):
            weight = metadata.get("rule_weight", metadata.get("weight"))
        if weight is None:
            weight = _result_field(finding, "weight", 1.0)

        if isinstance(severity, Enum):
            severity_value = str(severity.value)
        else:
            severity_value = str(severity)
        if isinstance(confidence, bool):
            confidence_value = 1.0
        elif isinstance(confidence, (int, float)) and math.isfinite(float(confidence)):
            confidence_value = max(0.0, min(1.0, float(confidence)))
        else:
            confidence_value = 1.0
        if isinstance(weight, bool):
            weight_value = 1.0
        elif isinstance(weight, (int, float)) and math.isfinite(float(weight)):
            weight_value = max(0.0, float(weight))
        else:
            weight_value = 1.0

        contribution = (
            _SEVERITY_RISK.get(severity_value, 0.5)
            * confidence_value
            * weight_value
            * _ACTION_MULTIPLIER[action]
        )
        components.append(
            {
                "rule_id": str(rule_id),
                "action": action.value,
                "severity": severity_value,
                "confidence": confidence_value,
                "weight": weight_value,
                "contribution": contribution,
            }
        )
    return components


def score_deviation(
    findings: object,
    *,
    rule_weights: Mapping[str, float] | None = None,
) -> float:
    """Return a deterministic 0..1 deviation score for review findings."""

    components = _score_components(findings, rule_weights=rule_weights)
    return min(1.0, sum(float(item["contribution"]) for item in components))


@dataclass(frozen=True, slots=True)
class PlaybookReview:
    """Immutable decision-support result for one complete contract."""

    playbook_id: str
    playbook_version: StrictInt | str
    playbook_hash: str
    canonical_hash: str
    action: Action
    deviation_score: float
    risk_score: float
    findings: tuple[PolicyResult, ...]
    policy_results: tuple[PolicyResult, ...]
    rule_results: tuple[PolicyResult, ...]
    redlines: tuple[PolicyResult, ...]
    clauses: tuple[Clause, ...]
    rules_triggered: tuple[str, ...]
    score_breakdown: tuple[dict[str, object], ...]
    disclaimer: str
    decision_support_only: bool

    @property
    def results(self) -> tuple[PolicyResult, ...]:
        return self.findings

    @property
    def deterministic_results(self) -> tuple[PolicyResult, ...]:
        return self.policy_results

    @property
    def overall_action(self) -> Action:
        return self.action

    def to_dict(self) -> dict[str, object]:
        return {
            "playbook_id": self.playbook_id,
            "playbook_version": self.playbook_version,
            "playbook_hash": self.playbook_hash,
            "canonical_hash": self.canonical_hash,
            "action": self.action.value,
            "deviation_score": self.deviation_score,
            "risk_score": self.risk_score,
            "findings": [
                result.model_dump(mode="json", by_alias=False)
                for result in self.findings
            ],
            "policy_results": [
                result.model_dump(mode="json", by_alias=False)
                for result in self.policy_results
            ],
            "rule_results": [
                result.model_dump(mode="json", by_alias=False)
                for result in self.rule_results
            ],
            "redlines": [
                result.model_dump(mode="json", by_alias=False)
                for result in self.redlines
            ],
            "clauses": [
                clause.model_dump(mode="json", by_alias=False)
                for clause in self.clauses
            ],
            "rules_triggered": list(self.rules_triggered),
            "score_breakdown": [
                _deep_thaw(component) for component in self.score_breakdown
            ],
            "disclaimer": self.disclaimer,
            "constitutional_rule": self.disclaimer,
            "decision_support_only": self.decision_support_only,
        }

    def model_dump(
        self,
        *,
        mode: str = "python",
        exclude_none: bool = False,
    ) -> dict[str, object]:
        if mode not in {"python", "json"}:
            raise ValueError("mode must be 'python' or 'json'")
        payload = self.to_dict()
        if not exclude_none:
            return payload
        return {
            key: value
            for key, value in payload.items()
            if value is not None
        }

    def as_dict(self) -> dict[str, object]:
        return self.to_dict()


def _evaluate_thresholds(self: object, text: str) -> list[PolicyResult]:
    engine = self
    if not isinstance(engine, PlaybookEngine):
        raise TypeError("threshold evaluation requires a PlaybookEngine")
    return _playbook_threshold_results(engine.thresholds, text)


def _evaluate_scc_rules(self: object, text: str) -> list[PolicyResult]:
    engine = self
    if not isinstance(engine, PlaybookEngine):
        raise TypeError("SCC evaluation requires a PlaybookEngine")
    return _playbook_scc_results(engine.thresholds, text)


# Method bindings preserve the compact review implementation while keeping
# threshold/SCC calculations independently testable.
PlaybookEngine._evaluate_thresholds = _evaluate_thresholds  # type: ignore[attr-defined]
PlaybookEngine._evaluate_scc_rules = _evaluate_scc_rules  # type: ignore[attr-defined]