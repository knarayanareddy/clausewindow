from datetime import datetime, timezone

import pytest
from pydantic import TypeAdapter, ValidationError

from clausewindow import (
    Action,
    Clause,
    ContractReviewReceipt,
    PlaybookRule,
    PolicyResult,
)


SHA_A = 'a' * 64
SHA_B = 'b' * 64


def test_action_values_and_validation():
    assert [action.value for action in Action] == ['allow', 'queue', 'block']
    assert Action.ALLOW == 'allow'
    assert TypeAdapter(Action).validate_python('queue') is Action.QUEUE
    with pytest.raises(ValidationError):
        TypeAdapter(Action).validate_python('approve')


@pytest.mark.parametrize(
    'model',
    [Clause, PlaybookRule, PolicyResult, ContractReviewReceipt],
)
def test_models_generate_json_schemas(model):
    schema = model.model_json_schema()
    assert schema['type'] == 'object'


def test_clause_aliases_offsets_and_properties():
    clause = Clause(
        id=' clause-11 ',
        text='Liability is capped at twelve months of fees.',
        start_offset=120,
        end_offset=176,
        section=' 11 ',
        schedule=' Schedule 1 ',
        source=' body ',
        page_number=7,
    )

    assert clause.clause_id == 'clause-11'
    assert clause.id == 'clause-11'
    assert clause.section == '11'
    assert clause.schedule == 'Schedule 1'
    assert clause.source == 'body'
    assert clause.offsets == (120, 176)
    assert clause.start == 120
    assert clause.end == 176
    assert clause.model_dump()['clause_id'] == 'clause-11'


@pytest.mark.parametrize(
    'overrides',
    [
        {'start_offset': -1},
        {'end_offset': 10},
        {'text': '   '},
        {'clause_id': '   '},
        {'page_number': True},
        {'page_number': 0},
        {'source': '   '},
    ],
)
def test_clause_rejects_invalid_spans_and_fields(overrides):
    values = {
        'clause_id': 'clause-1',
        'text': 'A valid clause.',
        'start_offset': 10,
        'end_offset': 20,
    }
    values.update(overrides)
    with pytest.raises(ValidationError):
        Clause(**values)


def test_clause_forbids_unknown_fields():
    with pytest.raises(ValidationError, match='extra_forbidden'):
        Clause(
            clause_id='clause-1',
            text='A valid clause.',
            start_offset=0,
            end_offset=5,
            unexpected=True,
        )


def test_playbook_rule_normalizes_regex_and_targeting_fields():
    rule = PlaybookRule(
        id=' liability-cap ',
        name=' Liability cap ',
        description='Detect liability-cap overrides.',
        reason_code='heuristic_cap',
        action='block',
        severity='critical',
        match_type='regex',
        pattern=r'liability.{0,30}uncapped',
        patterns=['data breach', 'uncapped liability'],
        expected='liability cap',
        clause_type=' liability ',
        section=' 11 ',
        confidence=0.9,
        priority=10,
    )

    assert rule.rule_id == 'liability-cap'
    assert rule.id == 'liability-cap'
    assert rule.name == 'Liability cap'
    assert rule.action is Action.BLOCK
    assert rule.severity == 'critical'
    assert rule.patterns == ('data breach', 'uncapped liability')
    assert rule.expected_text == 'liability cap'
    assert rule.clause_type == 'liability'
    assert rule.section == '11'


def test_playbook_rule_defaults_to_safe_queue_action():
    rule = PlaybookRule(
        rule_id='semantic-1',
        description='A semantic cross-reference check.',
        reason_code='playbook_deviation',
        match_type='semantic',
    )

    assert rule.action is Action.QUEUE
    assert rule.severity == 'medium'
    assert rule.confidence == 1.0
    assert rule.enabled is True
    assert rule.pattern is None
    assert rule.patterns == ()


def test_playbook_rule_rejects_invalid_regex_and_blank_matchers():
    with pytest.raises(ValidationError, match='invalid regular expression'):
        PlaybookRule(
            rule_id='bad-regex',
            description='An invalid expression.',
            reason_code='bad_regex',
            match_type='regex',
            pattern='[',
        )

    with pytest.raises(ValidationError, match='at least one pattern'):
        PlaybookRule(
            rule_id='empty-regex',
            description='A regex without an expression.',
            reason_code='missing_pattern',
            match_type='regex',
        )

    with pytest.raises(ValidationError, match='must not be blank'):
        PlaybookRule(
            rule_id='blank-pattern',
            description='A rule with a blank expression.',
            reason_code='blank_pattern',
            pattern='   ',
        )

    with pytest.raises(ValidationError, match='must not be blank'):
        PlaybookRule(
            rule_id='blank-section',
            description='A targeted rule.',
            reason_code='blank_section',
            section='   ',
        )


def test_policy_result_aliases_evidence_and_properties():
    result = PolicyResult(
        action='allow',
        reason_code='policy_aligned',
        confidence=0.91,
        matched_clause_ids=[' clause-a ', 'clause-b'],
        offsets=[[10, 25], [80, 96]],
        rationale='The selected language matches the playbook.',
        finding_type='informational',
    )

    assert result.action is Action.ALLOW
    assert result.clause_ids == ['clause-a', 'clause-b']
    assert result.clause_offsets == [(10, 25), (80, 96)]
    assert result.offsets == [(10, 25), (80, 96)]
    assert result.message == 'The selected language matches the playbook.'
    assert result.explanation == result.message
    assert result.rationale == result.message
    assert result.finding == 'informational'


def test_policy_result_defaults_to_queue():
    result = PolicyResult(
        reason_code='manual_review',
        message='A reviewer must assess this language.',
    )
    assert result.action is Action.QUEUE
    assert result.clause_ids == []
    assert result.clause_offsets == []


@pytest.mark.parametrize('action', [Action.ALLOW, Action.QUEUE, Action.BLOCK])
def test_injection_result_is_forced_to_high_confidence_queue(action):
    result = PolicyResult(
        action=action,
        reason_code='injection_or_jailbreak',
        confidence=0.2,
        finding='prompt_injection',
        message='Adversarial instructions were intercepted.',
    )

    assert result.action is Action.QUEUE
    assert result.confidence >= 0.95


def test_schedule_four_walkaway_result_is_forced_to_queue():
    result = PolicyResult(
        action=Action.BLOCK,
        reason_code='heuristic_cap',
        finding='playbook_walkaway',
        confidence=1.0,
        clause_ids=['section-11', 'schedule-4'],
        clause_offsets=[(100, 150), (9000, 9100)],
        message='Schedule 4 conflicts with the main liability cap.',
    )

    assert result.action is Action.QUEUE
    assert result.offsets == [(100, 150), (9000, 9100)]


@pytest.mark.parametrize(
    'overrides',
    [
        {'clause_ids': ['clause-a', ' clause-a ']},
        {'clause_ids': ['   ']},
        {'clause_offsets': [[-1, 2]]},
        {'clause_offsets': [[4, 4]]},
        {'clause_offsets': [[8, 3]]},
        {'clause_offsets': [['1', '4']]},
        {'confidence': -0.01},
        {'confidence': 1.01},
    ],
)
def test_policy_result_rejects_invalid_evidence(overrides):
    values = {
        'action': Action.QUEUE,
        'reason_code': 'test_finding',
        'message': 'A test finding.',
    }
    values.update(overrides)
    with pytest.raises(ValidationError):
        PolicyResult(**values)


def test_receipt_accepts_aliases_and_normalizes_audit_data():
    result = PolicyResult(
        action=Action.QUEUE,
        reason_code='heuristic_cap',
        finding='playbook_walkaway',
        message='Schedule 4 overrides the main cap.',
    )
    receipt = ContractReviewReceipt(
        id=' receipt-001 ',
        contract_hash=('A' * 64),
        playbook_hash=SHA_B,
        signed_by=' Alice Counsel ',
        role='Qualified Lawyer',
        attestation=True,
        timestamp='2025-01-15T12:30:00+02:00',
        results=[result],
    )

    assert receipt.receipt_id == 'receipt-001'
    assert receipt.id == 'receipt-001'
    assert receipt.contract_sha256 == SHA_A
    assert receipt.contract_hash == SHA_A
    assert receipt.playbook_hash == SHA_B
    assert receipt.actor == 'Alice Counsel'
    assert receipt.signed_by == 'Alice Counsel'
    assert receipt.actor_role == 'qualified_lawyer'
    assert receipt.signed_at == datetime(2025, 1, 15, 10, 30, tzinfo=timezone.utc)
    assert receipt.results == [result]
    assert receipt.final_action is Action.QUEUE
    assert receipt.decision is Action.QUEUE


def test_receipt_defaults_to_generated_id_and_allow_for_clean_review():
    receipt = ContractReviewReceipt(
        contract_sha256=SHA_A,
        playbook_sha256=SHA_B,
        actor='Reviewing Counsel',
        actor_role='qualified_lawyer',
        qualified_lawyer_attested=True,
        signed_at=datetime.now(timezone.utc),
    )

    assert len(receipt.receipt_id) == 36
    assert receipt.results == []
    assert receipt.final_action is Action.ALLOW


def test_receipt_derives_strongest_policy_action():
    blocking_result = PolicyResult(
        action=Action.BLOCK,
        reason_code='prohibited_liability',
        message='The clause blocks the transaction.',
    )
    receipt = ContractReviewReceipt(
        receipt_id='receipt-blocking',
        contract_sha256=SHA_A,
        playbook_sha256=SHA_B,
        actor='Reviewing Counsel',
        actor_role='qualified_lawyer',
        qualified_lawyer_attested=True,
        signed_at=datetime.now(timezone.utc),
        policy_results=[blocking_result],
    )

    assert receipt.final_action is Action.BLOCK


def test_receipt_cannot_understate_a_policy_finding():
    queued_result = PolicyResult(
        action=Action.QUEUE,
        reason_code='playbook_deviation',
        message='Human review is required.',
    )
    receipt = ContractReviewReceipt(
        receipt_id='receipt-understated',
        contract_sha256=SHA_A,
        playbook_sha256=SHA_B,
        actor='Reviewing Counsel',
        actor_role='qualified_lawyer',
        qualified_lawyer_attested=True,
        signed_at=datetime.now(timezone.utc),
        policy_results=[queued_result],
        final_action=Action.ALLOW,
    )

    assert receipt.final_action is Action.QUEUE


@pytest.mark.parametrize(
    'overrides',
    [
        {'contract_hash': 'not-a-sha256'},
        {'playbook_hash': '1234'},
        {'actor': '   '},
        {'role': 'lawyer'},
        {'attestation': False},
        {'timestamp': datetime(2025, 1, 1, 12, 0)},
        {'unexpected': 'value'},
    ],
)
def test_receipt_rejects_invalid_audit_data(overrides):
    values = {
        'receipt_id': 'receipt-invalid',
        'contract_hash': SHA_A,
        'playbook_hash': SHA_B,
        'signed_by': 'Alice Counsel',
        'role': 'qualified_lawyer',
        'attestation': True,
        'timestamp': datetime.now(timezone.utc),
    }
    values.update(overrides)
    with pytest.raises(ValidationError):
        ContractReviewReceipt(**values)
