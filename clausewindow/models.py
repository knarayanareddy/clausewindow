'''Strict domain models for contract review and signed audit receipts.'''

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Literal
from uuid import uuid4

from pydantic import (
    AliasChoices,
    BaseModel,
    ConfigDict,
    Field,
    StrictBool,
    StrictInt,
    field_validator,
    model_validator,
)


class Action(str, Enum):
    '''Actions that may be routed to a human reviewer.'''

    ALLOW = 'allow'
    QUEUE = 'queue'
    BLOCK = 'block'


class Clause(BaseModel):
    '''A contiguous clause and its half-open offsets in the full document.'''

    model_config = ConfigDict(
        extra='forbid',
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    clause_id: str = Field(
        min_length=1,
        max_length=200,
        validation_alias=AliasChoices('clause_id', 'id'),
    )
    text: str = Field(min_length=1)
    start_offset: int = Field(ge=0, strict=True)
    end_offset: int = Field(ge=0, strict=True)
    section: str | None = Field(default=None, max_length=500)
    schedule: str | None = Field(default=None, max_length=500)
    source: str = Field(default='body', min_length=1, max_length=100)
    page_number: int | None = Field(default=None, ge=1, strict=True)
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator('section', 'schedule', 'source')
    @classmethod
    def reject_blank_labels(cls, value: str | None) -> str | None:
        if value is not None and not value.strip():
            raise ValueError('labels must not be blank')
        return value

    @model_validator(mode='after')
    def validate_span(self) -> Clause:
        if self.end_offset <= self.start_offset:
            raise ValueError('end_offset must be greater than start_offset')
        return self

    @property
    def id(self) -> str:
        return self.clause_id

    @property
    def start(self) -> int:
        return self.start_offset

    @property
    def end(self) -> int:
        return self.end_offset

    @property
    def offsets(self) -> tuple[int, int]:
        return self.start_offset, self.end_offset


class PlaybookRule(BaseModel):
    '''A versionable rule that maps contract evidence to a review action.'''

    model_config = ConfigDict(
        extra='forbid',
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    rule_id: str = Field(
        min_length=1,
        max_length=200,
        validation_alias=AliasChoices('rule_id', 'id'),
    )
    name: str | None = Field(default=None, max_length=300)
    description: str = Field(min_length=1, max_length=2000)
    reason_code: str = Field(min_length=1, max_length=200)
    action: Action = Action.QUEUE
    severity: Literal['info', 'low', 'medium', 'high', 'critical'] = 'medium'
    match_type: Literal['literal', 'regex', 'semantic', 'cross_reference'] = 'literal'
    pattern: str | None = Field(
        default=None,
        max_length=4000,
        validation_alias=AliasChoices('pattern', 'match_pattern'),
    )
    patterns: tuple[str, ...] = ()
    expected_text: str | None = Field(
        default=None,
        max_length=4000,
        validation_alias=AliasChoices('expected_text', 'expected'),
    )
    clause_type: str | None = Field(default=None, max_length=300)
    section: str | None = Field(default=None, max_length=500)
    schedule: str | None = Field(default=None, max_length=500)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    priority: int = Field(default=100, ge=0, strict=True)
    weight: float = Field(default=1.0, ge=0.0)
    enabled: StrictBool = True
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator('name', 'pattern', 'clause_type', 'section', 'schedule')
    @classmethod
    def normalize_optional_text(cls, value: str | None) -> str | None:
        if value is None:
            return None
        cleaned = value.strip()
        if not cleaned:
            raise ValueError('optional rule text must not be blank')
        return cleaned

    @field_validator('patterns')
    @classmethod
    def normalize_patterns(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        normalized: list[str] = []
        for value in values:
            cleaned = value.strip()
            if not cleaned:
                raise ValueError('patterns must not contain blank entries')
            normalized.append(cleaned)
        return tuple(normalized)

    @model_validator(mode='after')
    def validate_regex(self) -> PlaybookRule:
        if self.match_type == 'regex':
            expressions = tuple(
                expression for expression in (self.pattern, *self.patterns) if expression
            )
            if not expressions:
                raise ValueError('regex rules require at least one pattern')
            for expression in expressions:
                try:
                    re.compile(expression)
                except re.error as exc:
                    raise ValueError(f'invalid regular expression {expression!r}: {exc}') from exc
        return self

    @property
    def id(self) -> str:
        return self.rule_id


class PolicyResult(BaseModel):
    '''A deterministic policy finding with evidence references and routing.'''

    model_config = ConfigDict(
        extra='forbid',
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    action: Action = Action.QUEUE
    reason_code: str = Field(min_length=1, max_length=200)
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    finding: str | None = Field(
        default=None,
        max_length=200,
        validation_alias=AliasChoices('finding', 'finding_type', 'flag'),
    )
    rule_id: str | None = Field(default=None, max_length=200)
    clause_ids: list[str] = Field(
        default_factory=list,
        validation_alias=AliasChoices('clause_ids', 'matched_clause_ids'),
    )
    clause_offsets: list[tuple[StrictInt, StrictInt]] = Field(
        default_factory=list,
        validation_alias=AliasChoices('clause_offsets', 'offsets'),
    )
    message: str = Field(
        min_length=1,
        max_length=5000,
        validation_alias=AliasChoices('message', 'explanation', 'rationale'),
    )
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator('clause_ids')
    @classmethod
    def normalize_clause_ids(cls, values: list[str]) -> list[str]:
        normalized: list[str] = []
        seen: set[str] = set()
        for value in values:
            cleaned = value.strip()
            if not cleaned:
                raise ValueError('clause_ids must not contain blank identifiers')
            if cleaned in seen:
                raise ValueError(f'duplicate clause_id: {cleaned}')
            seen.add(cleaned)
            normalized.append(cleaned)
        return normalized

    @field_validator('clause_offsets')
    @classmethod
    def validate_offsets(
        cls,
        values: list[tuple[StrictInt, StrictInt]],
    ) -> list[tuple[StrictInt, StrictInt]]:
        normalized: list[tuple[StrictInt, StrictInt]] = []
        for start, end in values:
            if start < 0:
                raise ValueError('offset starts must be non-negative')
            if end <= start:
                raise ValueError('offset ends must be greater than offset starts')
            normalized.append((start, end))
        return normalized

    @model_validator(mode='after')
    def enforce_safety_routes(self) -> PolicyResult:
        reason = self.reason_code.casefold()
        finding = self.finding.casefold() if self.finding else None

        if reason == 'injection_or_jailbreak':
            object.__setattr__(self, 'action', Action.QUEUE)
            if self.confidence < 0.95:
                object.__setattr__(self, 'confidence', 0.95)

        if reason == 'heuristic_cap' and finding == 'playbook_walkaway':
            object.__setattr__(self, 'action', Action.QUEUE)

        return self

    @property
    def explanation(self) -> str:
        return self.message

    @property
    def rationale(self) -> str:
        return self.message

    @property
    def offsets(self) -> list[tuple[StrictInt, StrictInt]]:
        return self.clause_offsets


class ContractReviewReceipt(BaseModel):
    '''A signed, human-attested audit receipt bound to exact input hashes.'''

    model_config = ConfigDict(
        extra='forbid',
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_assignment=True,
    )

    receipt_id: str = Field(
        default_factory=lambda: str(uuid4()),
        min_length=1,
        max_length=200,
        validation_alias=AliasChoices('receipt_id', 'id'),
    )
    contract_sha256: str = Field(
        validation_alias=AliasChoices('contract_sha256', 'contract_hash'),
    )
    playbook_sha256: str = Field(
        validation_alias=AliasChoices('playbook_sha256', 'playbook_hash'),
    )
    actor: str = Field(
        min_length=1,
        max_length=500,
        validation_alias=AliasChoices('actor', 'signed_by'),
    )
    actor_role: str = Field(
        min_length=1,
        max_length=100,
        validation_alias=AliasChoices('actor_role', 'role'),
    )
    qualified_lawyer_attested: StrictBool = Field(
        validation_alias=AliasChoices(
            'qualified_lawyer_attested',
            'attestation',
            'attested',
        ),
    )
    signed_at: datetime = Field(
        validation_alias=AliasChoices('signed_at', 'timestamp'),
    )
    policy_results: list[PolicyResult] = Field(
        default_factory=list,
        validation_alias=AliasChoices('policy_results', 'results'),
    )
    final_action: Action | None = Field(
        default=None,
        validation_alias=AliasChoices('final_action', 'decision'),
    )
    contract_name: str | None = Field(default=None, max_length=1000)
    playbook_version: str | None = Field(default=None, max_length=500)
    metadata: dict[str, object] = Field(default_factory=dict)

    @field_validator('contract_sha256', 'playbook_sha256')
    @classmethod
    def normalize_hash(cls, value: str) -> str:
        if re.fullmatch(r'[0-9a-fA-F]{64}', value) is None:
            raise ValueError('SHA-256 hashes must contain exactly 64 hexadecimal characters')
        return value.lower()

    @field_validator('actor_role')
    @classmethod
    def normalize_actor_role(cls, value: str) -> str:
        normalized = re.sub(r'[\s_-]+', '_', value.strip().casefold())
        if normalized != 'qualified_lawyer':
            raise ValueError('actor_role must be qualified_lawyer')
        return normalized

    @field_validator('qualified_lawyer_attested')
    @classmethod
    def require_attestation(cls, value: bool) -> bool:
        if value is not True:
            raise ValueError('a qualified-lawyer attestation is required')
        return value

    @field_validator('signed_at')
    @classmethod
    def require_timezone(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError('signed_at must include a timezone')
        return value.astimezone(timezone.utc)

    @model_validator(mode='after')
    def derive_final_action(self) -> ContractReviewReceipt:
        action_rank = {
            Action.ALLOW: 0,
            Action.QUEUE: 1,
            Action.BLOCK: 2,
        }
        strongest = max(
            (result.action for result in self.policy_results),
            key=action_rank.__getitem__,
            default=Action.ALLOW,
        )
        if self.final_action is None or action_rank[self.final_action] < action_rank[strongest]:
            object.__setattr__(self, 'final_action', strongest)
        return self

    @property
    def id(self) -> str:
        return self.receipt_id

    @property
    def contract_hash(self) -> str:
        return self.contract_sha256

    @property
    def playbook_hash(self) -> str:
        return self.playbook_sha256

    @property
    def signed_by(self) -> str:
        return self.actor

    @property
    def timestamp(self) -> datetime:
        return self.signed_at

    @property
    def results(self) -> list[PolicyResult]:
        return self.policy_results

    @property
    def decision(self) -> Action:
        if self.final_action is None:
            raise RuntimeError('final_action was not initialized')
        return self.final_action
