"""SQLite-backed immutable receipts, HMAC signatures, and audit chains.

Receipt payloads are immutable after insertion. Qualified-lawyer sign-off is
stored separately as append-only state and as an ``actor=human`` audit event.
The original review evidence therefore remains reproducible and verifiable.

A signing key can be supplied directly or through
``CLAUSEWINDOW_RECEIPT_SIGNING_KEY``. Without a configured key, hash-chain
integrity checks remain available, but HMAC authenticity cannot be verified.

This service records decision support only. It does not provide legal advice.
A qualified lawyer must sign the final decision.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import sqlite3
import threading
from collections.abc import Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4


DEFAULT_DATABASE_PATH = Path("receipts.db")
SIGNING_KEY_ENV = "CLAUSEWINDOW_RECEIPT_SIGNING_KEY"

_GENESIS_HASH = "0" * 64
_AWAITING_SIGNOFF_STATUS = "awaiting_qualified_lawyer_signoff"
_SIGNED_STATUS = "qualified_lawyer_signed"
_SIGNABLE_DECISIONS = frozenset(
    {"approved", "rejected", "revision_requested"}
)

_REQUIRED_RECEIPT_FIELDS = (
    "receipt_id",
    "review_id",
    "status",
    "created_at",
    "contract_hash",
    "playbook_hash",
    "receipt_hash",
)
_RECEIPT_CORE_COLUMNS = {
    "receipt_id": "receipt_id",
    "review_id": "review_id",
    "status": "status",
    "created_at": "created_at",
    "contract_hash": "contract_hash",
    "playbook_hash": "playbook_hash",
    "receipt_hash": "receipt_hash",
}
_RECEIPT_PAYLOAD_COLUMNS = (
    "payload_json",
    "receipt_json",
    "document_json",
)
_RECEIPT_FIELD_JSON_COLUMNS = {
    "findings_json": "findings",
    "redlines_json": "redlines",
    "human_sign_off_json": "human_sign_off",
    "playbook_snapshot_json": "playbook_snapshot",
    "metadata_json": "metadata",
}
_AUDIT_PAYLOAD_COLUMNS = (
    "event_data_json",
    "payload_json",
    "details_json",
)
_SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")
_AFFIRMATIVE_QUALIFICATIONS = frozenset(
    {
        "1",
        "active",
        "admitted",
        "approved",
        "bar_admitted",
        "confirmed",
        "lawyer",
        "qualified",
        "qualified_lawyer",
        "qualified lawyer",
        "true",
        "yes",
    }
)
_NON_LAWYSTER_ROLES = frozenset(
    {
        "administrator",
        "analyst",
        "contract_manager",
        "engineer",
        "legal_assistant",
        "legal operations",
        "legal_operations",
        "paralegal",
        "reviewer",
        "sales",
        "staff",
    }
)
_QUALIFIED_LAWYER_ROLES = frozenset(
    {
        "associate",
        "attorney",
        "counsel",
        "lawyer",
        "partner",
        "qualified_lawyer",
        "qualified lawyer",
    }
)


class StorageError(RuntimeError):
    """Base receipt-storage failure."""


class ReceiptNotFoundError(StorageError):
    """Raised when a receipt identifier does not exist."""


class ReceiptConflictError(StorageError):
    """Raised when an immutable receipt identifier is reused."""


class InvalidSignoffError(StorageError):
    """Raised when qualified-lawyer sign-off is invalid or duplicated."""


class AuditChainError(StorageError):
    """Raised when an audit event cannot be recorded or verified safely."""


def _utc_now() -> str:
    """Return a sortable UTC timestamp."""

    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _json_default(value: object) -> object:
    """Convert supported domain values into canonical JSON values."""

    if isinstance(value, Enum):
        return value.value
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    if isinstance(value, set):
        return sorted(value, key=str)
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=False)
    raise TypeError(
        f"Value of type {type(value).__name__} is not JSON serializable."
    )


def canonical_json(value: object) -> str:
    """Serialize a value deterministically for hashing and storage."""

    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
        default=_json_default,
    )


def _sha256(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def _normalize_payload(
    value: Mapping[str, Any] | Any,
) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", by_alias=False)
    elif is_dataclass(value):
        value = asdict(value)

    if not isinstance(value, Mapping):
        raise ValueError(
            "Receipt payload must be a mapping or Pydantic model."
        )

    try:
        normalized = json.loads(canonical_json(dict(value)))
    except (TypeError, ValueError) as exc:
        raise ValueError(
            "Receipt payload must be JSON serializable."
        ) from exc

    if not isinstance(normalized, dict):
        raise ValueError("Receipt payload must serialize to an object.")
    return normalized


def _normalize_object(
    value: Mapping[str, Any] | Any,
    *,
    description: str,
) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        value = value.model_dump(mode="json", by_alias=False)
    elif is_dataclass(value):
        value = asdict(value)
    if not isinstance(value, Mapping):
        raise ValueError(f"{description} must be a mapping.")
    try:
        normalized = json.loads(canonical_json(dict(value)))
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{description} must be JSON serializable.") from exc
    if not isinstance(normalized, dict):
        raise ValueError(f"{description} must serialize to an object.")
    return normalized


def _require_identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be blank.")
    if len(normalized) > 200:
        raise ValueError(f"{field_name} must not exceed 200 characters.")
    return normalized


def _require_hash(value: object, field_name: str) -> str:
    normalized = _require_identifier(value, field_name)
    if _SHA256_RE.fullmatch(normalized) is None:
        raise ValueError(f"{field_name} must be a SHA-256 hex digest.")
    return normalized


def _validate_timestamp(value: object, field_name: str) -> str:
    normalized = _require_identifier(value, field_name)
    candidate = normalized[:-1] + "+00:00" if normalized.endswith("Z") else normalized
    try:
        datetime.fromisoformat(candidate)
    except ValueError as exc:
        raise ValueError(
            f"{field_name} must be an ISO-8601 timestamp."
        ) from exc
    return normalized


def _decode_json(value: object, default: object) -> object:
    if value is None or value == "":
        return default
    if isinstance(value, (dict, list, int, float, bool)):
        return value
    if isinstance(value, bytes):
        value = value.decode("utf-8", errors="strict")
    try:
        return json.loads(value)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise StorageError("Stored JSON contains invalid data.") from exc


def _table_exists(
    connection: sqlite3.Connection,
    table_name: str,
) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?",
        (table_name,),
    ).fetchone()
    return row is not None


def _table_columns(
    connection: sqlite3.Connection,
    table_name: str,
) -> set[str]:
    return {
        str(row[1])
        for row in connection.execute(f"PRAGMA table_info({table_name})")
    }


def _ensure_schema(connection: sqlite3.Connection) -> None:
    """Create or migrate the receipt schema before dependent indexes exist."""

    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS receipts (
            receipt_id TEXT PRIMARY KEY,
            review_id TEXT,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            contract_hash TEXT NOT NULL,
            playbook_hash TEXT NOT NULL,
            receipt_hash TEXT NOT NULL,
            payload_json TEXT,
            findings_json TEXT,
            redlines_json TEXT,
            human_sign_off_json TEXT,
            playbook_snapshot_json TEXT,
            metadata_json TEXT,
            receipt_signature TEXT,
            signed_at TEXT,
            human_signer_id TEXT,
            human_decision TEXT
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            receipt_id TEXT NOT NULL,
            review_id TEXT,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            event_data_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL,
            sequence_no INTEGER,
            event_signature TEXT
        );

        CREATE TABLE IF NOT EXISTS human_signoffs (
            receipt_id TEXT PRIMARY KEY,
            review_id TEXT NOT NULL,
            actor TEXT NOT NULL,
            signer_id TEXT NOT NULL,
            decision TEXT NOT NULL,
            signed_at TEXT NOT NULL,
            signoff_json TEXT NOT NULL,
            signoff_hash TEXT NOT NULL,
            signoff_signature TEXT
        );
        """
    )

    receipt_additions = {
        "review_id": "TEXT",
        "payload_json": "TEXT",
        "findings_json": "TEXT",
        "redlines_json": "TEXT",
        "human_sign_off_json": "TEXT",
        "playbook_snapshot_json": "TEXT",
        "metadata_json": "TEXT",
        "receipt_signature": "TEXT",
        "signed_at": "TEXT",
        "human_signer_id": "TEXT",
        "human_decision": "TEXT",
    }
    receipt_columns = _table_columns(connection, "receipts")
    for name, declaration in receipt_additions.items():
        if name not in receipt_columns:
            connection.execute(
                f"ALTER TABLE receipts ADD COLUMN {name} {declaration}"
            )

    audit_additions = {
        "review_id": "TEXT",
        "sequence_no": "INTEGER",
        "event_signature": "TEXT",
    }
    audit_columns = _table_columns(connection, "audit_events")
    for name, declaration in audit_additions.items():
        if name not in audit_columns:
            connection.execute(
                f"ALTER TABLE audit_events ADD COLUMN {name} {declaration}"
            )

    _backfill_legacy_receipts(connection)
    _backfill_legacy_audit_events(connection)

    # Dependent indexes intentionally run only after all columns are present.
    connection.executescript(
        """
        CREATE INDEX IF NOT EXISTS
            clausewindow_audit_receipt_created_idx
        ON audit_events(receipt_id, created_at, sequence_no);

        CREATE INDEX IF NOT EXISTS
            clausewindow_audit_receipt_sequence_idx
        ON audit_events(receipt_id, sequence_no);

        CREATE INDEX IF NOT EXISTS
            clausewindow_receipt_review_created_idx
        ON receipts(review_id, created_at);

        CREATE INDEX IF NOT EXISTS
            clausewindow_receipt_status_created_idx
        ON receipts(status, created_at);
        """
    )
    connection.execute("PRAGMA user_version = 1")


def _legacy_payload_from_row(row: sqlite3.Row) -> dict[str, Any]:
    columns = set(row.keys())
    for payload_column in _RECEIPT_PAYLOAD_COLUMNS:
        if payload_column in columns and row[payload_column]:
            decoded = _decode_json(row[payload_column], None)
            if isinstance(decoded, dict):
                return decoded

    payload: dict[str, Any] = {}
    for field, column in _RECEIPT_CORE_COLUMNS.items():
        if column in columns and row[column] is not None:
            payload[field] = row[column]
    for json_column, field in _RECEIPT_FIELD_JSON_COLUMNS.items():
        if json_column in columns and row[json_column] is not None:
            payload[field] = _decode_json(row[json_column], None)
    return payload


def _backfill_legacy_receipts(connection: sqlite3.Connection) -> None:
    columns = _table_columns(connection, "receipts")
    for row in connection.execute("SELECT * FROM receipts").fetchall():
        updates: dict[str, object] = {}

        if "payload_json" in columns and not row["payload_json"]:
            payload = _legacy_payload_from_row(row)
            if payload:
                updates["payload_json"] = canonical_json(payload)
                if not row["review_id"] and payload.get("review_id"):
                    updates["review_id"] = payload["review_id"]

        if not row["review_id"] and updates.get("review_id") is None:
            payload = _legacy_payload_from_row(row)
            if payload.get("review_id"):
                updates["review_id"] = payload["review_id"]

        if updates:
            assignments = ", ".join(f"{name} = ?" for name in updates)
            connection.execute(
                f"UPDATE receipts SET {assignments} WHERE receipt_id = ?",
                (*updates.values(), row["receipt_id"]),
            )


def _backfill_legacy_audit_events(connection: sqlite3.Connection) -> None:
    columns = _table_columns(connection, "audit_events")
    rows = connection.execute(
        "SELECT rowid AS _rowid, * FROM audit_events ORDER BY rowid"
    ).fetchall()

    for sequence, row in enumerate(rows, start=1):
        updates: dict[str, object] = {"sequence_no": sequence}
        review_id = row["review_id"] if "review_id" in columns else None
        if not review_id:
            receipt = connection.execute(
                "SELECT review_id FROM receipts WHERE receipt_id = ?",
                (row["receipt_id"],),
            ).fetchone()
            review_id = receipt["review_id"] if receipt is not None else None
        if review_id:
            updates["review_id"] = review_id

        assignments = ", ".join(f"{name} = ?" for name in updates)
        connection.execute(
            f"UPDATE audit_events SET {assignments} WHERE event_id = ?",
            (*updates.values(), row["event_id"]),
        )


class ReceiptStore:
    """Persist immutable review receipts and hash-chained audit events."""

    def __init__(
        self,
        database_path: str | Path | None = None,
        signing_key: str | bytes | None = None,
        *,
        timeout: float = 30.0,
    ) -> None:
        if database_path is None:
            database_path = Path(
                os.environ.get(
                    "CLAUSEWINDOW_RECEIPTS_DB",
                    str(DEFAULT_DATABASE_PATH),
                )
            )

        self.database_path = str(database_path)
        self._lock = threading.RLock()
        self._closed = False
        self._signing_key = self._resolve_signing_key(signing_key)

        if self.database_path != ":memory:" and not self.database_path.startswith(
            "file:"
        ):
            parent = Path(self.database_path).expanduser().resolve().parent
            parent.mkdir(parents=True, exist_ok=True)

        self._connection = sqlite3.connect(
            self.database_path,
            timeout=timeout,
            check_same_thread=False,
            isolation_level=None,
            uri=self.database_path.startswith("file:"),
        )
        self._connection.row_factory = sqlite3.Row
        self._connection.execute("PRAGMA foreign_keys = ON")
        self._connection.execute("PRAGMA busy_timeout = 30000")
        self._connection.execute("PRAGMA journal_mode = WAL")
        self._connection.execute("PRAGMA synchronous = NORMAL")
        _ensure_schema(self._connection)

    @staticmethod
    def _resolve_signing_key(
        signing_key: str | bytes | None,
    ) -> bytes | None:
        value = signing_key
        if value is None:
            value = os.environ.get(SIGNING_KEY_ENV)
        if value is None:
            return None
        if isinstance(value, str):
            encoded = value.encode("utf-8")
        elif isinstance(value, bytes):
            encoded = value
        else:
            raise TypeError("signing_key must be str, bytes, or None.")
        if not encoded:
            raise ValueError("signing_key must not be blank.")
        return encoded

    @property
    def signing_key_id(self) -> str | None:
        if self._signing_key is None:
            return None
        return hashlib.sha256(self._signing_key).hexdigest()[:16]

    def _require_connection(self) -> sqlite3.Connection:
        if self._closed or self._connection is None:
            raise StorageError("Receipt store is closed.")
        try:
            self._connection.execute("SELECT 1").fetchone()
        except sqlite3.Error as exc:
            raise StorageError("Receipt database is unavailable.") from exc
        return self._connection

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = self._require_connection()
        with self._lock:
            connection.execute("BEGIN IMMEDIATE")
            try:
                yield connection
            except BaseException:
                connection.rollback()
                raise
            else:
                connection.commit()

    def _sign(self, domain: str, value: object) -> str | None:
        if self._signing_key is None:
            return None
        message = (
            b"clausewindow\0"
            + domain.encode("utf-8")
            + b"\0"
            + canonical_json(value).encode("utf-8")
        )
        return hmac.new(
            self._signing_key,
            message,
            hashlib.sha256,
        ).hexdigest()

    def _receipt_row(
        self,
        connection: sqlite3.Connection,
        receipt_id: str,
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if row is None:
            raise ReceiptNotFoundError(
                f"Receipt {receipt_id!r} was not found."
            )
        return row

    def _stored_payload(self, row: sqlite3.Row) -> dict[str, Any]:
        columns = set(row.keys())
        payload: dict[str, Any] | None = None
        for payload_column in _RECEIPT_PAYLOAD_COLUMNS:
            if payload_column in columns and row[payload_column]:
                decoded = _decode_json(row[payload_column], None)
                if isinstance(decoded, dict):
                    payload = decoded
                    break
        if payload is None:
            payload = _legacy_payload_from_row(row)
        if not payload:
            raise StorageError("Stored receipt payload is missing or invalid.")
        return payload

    def _signoff_for_row(
        self,
        connection: sqlite3.Connection,
        receipt_id: str,
    ) -> dict[str, Any] | None:
        columns = _table_columns(connection, "receipts")
        if "human_sign_off_json" in columns:
            row = connection.execute(
                """
                SELECT signoff_json, signoff_signature
                FROM human_signoffs
                WHERE receipt_id = ?
                """,
                (receipt_id,),
            ).fetchone()
            if row is not None:
                decoded = _decode_json(row["signoff_json"], None)
                if not isinstance(decoded, dict):
                    raise StorageError("Stored human sign-off is invalid.")
                decoded["signoff_signature"] = row["signoff_signature"]
                return decoded

        receipt_row = connection.execute(
            "SELECT human_sign_off_json FROM receipts WHERE receipt_id = ?",
            (receipt_id,),
        ).fetchone()
        if receipt_row is None or not receipt_row["human_sign_off_json"]:
            return None
        decoded = _decode_json(
            receipt_row["human_sign_off_json"],
            None,
        )
        return decoded if isinstance(decoded, dict) else None

    def _receipt_to_dict(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> dict[str, Any]:
        payload = dict(self._stored_payload(row))
        columns = set(row.keys())

        for field, column in _RECEIPT_CORE_COLUMNS.items():
            if column in columns and row[column] is not None:
                payload[field] = row[column]
        for json_column, field in _RECEIPT_FIELD_JSON_COLUMNS.items():
            if (
                field == "human_sign_off"
                or json_column not in columns
                or row[json_column] is None
            ):
                continue
            decoded = _decode_json(row[json_column], None)
            if decoded is not None:
                payload[field] = decoded

        if "receipt_signature" in columns:
            payload["receipt_signature"] = row["receipt_signature"]

        signoff = self._signoff_for_row(connection, row["receipt_id"])
        if signoff is not None:
            payload["human_sign_off"] = signoff
            payload["status"] = _SIGNED_STATUS
            if signoff.get("signed_at") is not None:
                payload["signed_at"] = signoff["signed_at"]
        else:
            payload.setdefault("human_sign_off", None)

        return payload

    def save_receipt(
        self,
        receipt: Mapping[str, Any] | Any,
    ) -> dict[str, Any]:
        """Insert one immutable receipt and its genesis audit event."""

        payload = _normalize_payload(receipt)
        self._validate_receipt_payload(payload)
        receipt_id = _require_identifier(payload["receipt_id"], "receipt_id")
        review_id = _require_identifier(payload["review_id"], "review_id")

        signature = self._sign("receipt", payload)
        stored_payload = dict(payload)
        stored_payload.pop("receipt_signature", None)
        if signature is not None:
            stored_payload["receipt_signature"] = signature

        with self._transaction() as connection:
            existing = connection.execute(
                "SELECT 1 FROM receipts WHERE receipt_id = ?",
                (receipt_id,),
            ).fetchone()
            if existing is not None:
                raise ReceiptConflictError(
                    "Receipt identifiers are immutable and cannot be reused."
                )

            connection.execute(
                """
                INSERT INTO receipts (
                    receipt_id,
                    review_id,
                    status,
                    created_at,
                    contract_hash,
                    playbook_hash,
                    receipt_hash,
                    payload_json,
                    findings_json,
                    redlines_json,
                    human_sign_off_json,
                    playbook_snapshot_json,
                    metadata_json,
                    receipt_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    receipt_id,
                    review_id,
                    payload["status"],
                    payload["created_at"],
                    payload["contract_hash"],
                    payload["playbook_hash"],
                    payload["receipt_hash"],
                    canonical_json(stored_payload),
                    canonical_json(payload.get("findings", [])),
                    canonical_json(payload.get("redlines", [])),
                    None,
                    canonical_json(payload.get("playbook_snapshot")),
                    canonical_json(payload.get("metadata", {})),
                    signature,
                ),
            )

            self._append_audit_event(
                connection,
                receipt_id=receipt_id,
                review_id=review_id,
                event_type="receipt_created",
                actor="system",
                event_data={
                    "review_id": review_id,
                    "status": payload["status"],
                    "contract_hash": payload["contract_hash"],
                    "playbook_hash": payload["playbook_hash"],
                    "receipt_hash": payload["receipt_hash"],
                    "created_at": payload["created_at"],
                },
                created_at=_utc_now(),
            )

        return self.get_receipt(receipt_id)

    def get_receipt(
        self,
        receipt_id: str,
        *,
        verify: bool = False,
    ) -> dict[str, Any]:
        """Return a receipt together with append-only sign-off state."""

        normalized_id = _require_identifier(receipt_id, "receipt_id")
        with self._lock:
            connection = self._require_connection()
            row = self._receipt_row(connection, normalized_id)
            if verify and not self._verify_receipt_row(connection, row):
                raise StorageError("Receipt integrity verification failed.")
            return self._receipt_to_dict(connection, row)

    def list_receipts(
        self,
        *,
        review_id: str | None = None,
        status: str | None = None,
        limit: int | None = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List immutable receipts with stable ordering and pagination."""

        if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
            raise ValueError("offset must be a non-negative integer.")
        if limit is not None:
            if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
                raise ValueError("limit must be a non-negative integer or None.")

        normalized_review_id = (
            _require_identifier(review_id, "review_id")
            if review_id is not None
            else None
        )
        normalized_status = (
            _require_identifier(status, "status")
            if status is not None
            else None
        )

        clauses: list[str] = []
        parameters: list[object] = []
        if normalized_review_id is not None:
            clauses.append("review_id = ?")
            parameters.append(normalized_review_id)
        if normalized_status is not None:
            clauses.append(
                "(status = ? OR EXISTS ("
                "SELECT 1 FROM human_signoffs s "
                "WHERE s.receipt_id = receipts.receipt_id"
                "))"
            )
            parameters.append(normalized_status)

        query = "SELECT * FROM receipts"
        if clauses:
            query += " WHERE " + " AND ".join(clauses)
        query += " ORDER BY created_at DESC, receipt_id DESC"

        with self._lock:
            connection = self._require_connection()
            rows = connection.execute(query, parameters).fetchall()
            receipts = [
                self._receipt_to_dict(connection, row)
                for row in rows
            ]

        end = None if limit is None else offset + limit
        return receipts[offset:end]

    @staticmethod
    def _event_material(
        *,
        event_id: str,
        receipt_id: str,
        review_id: str,
        sequence_no: int,
        event_type: str,
        actor: str,
        event_data: Mapping[str, Any],
        created_at: str,
        previous_hash: str,
    ) -> dict[str, object]:
        return {
            "event_id": event_id,
            "receipt_id": receipt_id,
            "review_id": review_id,
            "sequence_no": sequence_no,
            "event_type": event_type,
            "actor": actor,
            "event_data": dict(event_data),
            "created_at": created_at,
            "previous_hash": previous_hash,
        }

    def _append_audit_event(
        self,
        connection: sqlite3.Connection,
        *,
        receipt_id: str,
        review_id: str,
        event_type: str,
        actor: str,
        event_data: Mapping[str, Any],
        created_at: str | None = None,
    ) -> dict[str, Any]:
        tail = connection.execute(
            """
            SELECT sequence_no, event_hash
            FROM audit_events
            WHERE receipt_id = ?
            ORDER BY sequence_no DESC, rowid DESC
            LIMIT 1
            """,
            (receipt_id,),
        ).fetchone()
        sequence_no = 1 if tail is None else int(tail["sequence_no"] or 0) + 1
        previous_hash = _GENESIS_HASH if tail is None else tail["event_hash"]

        normalized_event_type = _require_identifier(
            event_type,
            "event_type",
        )
        normalized_actor = _require_identifier(actor, "actor")
        normalized_created_at = _validate_timestamp(
            created_at or _utc_now(),
            "created_at",
        )
        normalized_event_data = _normalize_object(
            event_data,
            description="Audit event data",
        )

        event_id = str(uuid4())
        material = self._event_material(
            event_id=event_id,
            receipt_id=receipt_id,
            review_id=review_id,
            sequence_no=sequence_no,
            event_type=normalized_event_type,
            actor=normalized_actor,
            event_data=normalized_event_data,
            created_at=normalized_created_at,
            previous_hash=previous_hash,
        )
        event_hash = _sha256(material)
        event_signature = self._sign(
            "audit-event",
            {"event": material, "event_hash": event_hash},
        )

        connection.execute(
            """
            INSERT INTO audit_events (
                event_id,
                receipt_id,
                review_id,
                event_type,
                actor,
                event_data_json,
                created_at,
                previous_hash,
                event_hash,
                sequence_no,
                event_signature
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                receipt_id,
                review_id,
                normalized_event_type,
                normalized_actor,
                canonical_json(normalized_event_data),
                normalized_created_at,
                previous_hash,
                event_hash,
                sequence_no,
                event_signature,
            ),
        )
        return {
            "event_id": event_id,
            "receipt_id": receipt_id,
            "review_id": review_id,
            "event_type": normalized_event_type,
            "actor": normalized_actor,
            "event_data": normalized_event_data,
            "created_at": normalized_created_at,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
            "sequence_no": sequence_no,
            "event_signature": event_signature,
        }

    def record_audit_event(
        self,
        receipt_id: str,
        event_type: str,
        actor: str,
        event_data: Mapping[str, Any],
    ) -> dict[str, Any]:
        """Append an independently hashed audit event to a receipt chain."""

        normalized_receipt_id = _require_identifier(receipt_id, "receipt_id")
        normalized_event_data = _normalize_object(
            event_data,
            description="Audit event data",
        )
        with self._transaction() as connection:
            receipt = self._receipt_row(connection, normalized_receipt_id)
            review_id = _require_identifier(
                receipt["review_id"],
                "review_id",
            )
            return self._append_audit_event(
                connection,
                receipt_id=normalized_receipt_id,
                review_id=review_id,
                event_type=event_type,
                actor=actor,
                event_data=normalized_event_data,
            )

    def get_audit_events(
        self,
        receipt_id: str,
        *,
        verify: bool = False,
    ) -> list[dict[str, Any]]:
        """Return the ordered audit chain for one receipt."""

        normalized_receipt_id = _require_identifier(receipt_id, "receipt_id")
        with self._lock:
            connection = self._require_connection()
            self._receipt_row(connection, normalized_receipt_id)
            rows = connection.execute(
                """
                SELECT *
                FROM audit_events
                WHERE receipt_id = ?
                ORDER BY sequence_no ASC, rowid ASC
                """,
                (normalized_receipt_id,),
            ).fetchall()
            events = [self._audit_row_to_dict(row) for row in rows]

        if verify and not self._verify_event_rows(normalized_receipt_id, events):
            raise AuditChainError("Audit chain verification failed.")
        return events

    @staticmethod
    def _audit_row_to_dict(row: sqlite3.Row) -> dict[str, Any]:
        event_data = _decode_json(row["event_data_json"], {})
        return {
            "event_id": row["event_id"],
            "receipt_id": row["receipt_id"],
            "review_id": row["review_id"],
            "event_type": row["event_type"],
            "actor": row["actor"],
            "event_data": event_data,
            "created_at": row["created_at"],
            "previous_hash": row["previous_hash"],
            "event_hash": row["event_hash"],
            "sequence_no": (
                None
                if row["sequence_no"] is None
                else int(row["sequence_no"])
            ),
            "event_signature": row["event_signature"],
        }

    def _validate_receipt_payload(self, payload: Mapping[str, Any]) -> None:
        for field in _REQUIRED_RECEIPT_FIELDS:
            if field not in payload or payload[field] is None:
                raise ValueError(f"{field} is required.")

        _require_identifier(payload["receipt_id"], "receipt_id")
        _require_identifier(payload["review_id"], "review_id")
        status = _require_identifier(payload["status"], "status")
        if status != _AWAITING_SIGNOFF_STATUS:
            raise ValueError(
                "status must be awaiting_qualified_lawyer_signoff."
            )
        _validate_timestamp(payload["created_at"], "created_at")
        _require_hash(payload["contract_hash"], "contract_hash")
        _require_hash(payload["playbook_hash"], "playbook_hash")
        _require_hash(payload["receipt_hash"], "receipt_hash")
        if payload.get("human_sign_off") not in (None, {}, []):
            raise ValueError(
                "human_sign_off must be recorded after receipt creation."
            )

    def _validate_human_signoff(
        self,
        signoff: Mapping[str, Any],
    ) -> dict[str, Any]:
        normalized = _normalize_object(
            signoff,
            description="Human sign-off",
        )

        decision = normalized.get("decision")
        if (
            not isinstance(decision, str)
            or decision.strip().lower() not in _SIGNABLE_DECISIONS
        ):
            raise InvalidSignoffError(
                "Human sign-off decision must be a supported decision: "
                "approved, rejected, or revision_requested."
            )
        normalized["decision"] = decision.strip().lower()

        actor = normalized.get("actor")
        if not isinstance(actor, str) or actor.strip().lower() != "human":
            raise InvalidSignoffError(
                "Human sign-off actor must be exactly 'human'."
            )
        normalized["actor"] = "human"

        signer_id = normalized.get("signer_id")
        if not isinstance(signer_id, str) or not signer_id.strip():
            raise InvalidSignoffError(
                "Human sign-off must identify the qualified lawyer."
            )
        normalized["signer_id"] = signer_id.strip()

        role_value = normalized.get("role")
        normalized_role: str | None = None
        if role_value is not None:
            if not isinstance(role_value, str) or not role_value.strip():
                raise InvalidSignoffError(
                    "Human sign-off role must not be blank."
                )
            normalized_role = role_value.strip().lower().replace("-", "_")
            normalized["role"] = normalized_role
            if (
                normalized_role in _NON_LAWYSTER_ROLES
                or "paralegal" in normalized_role
            ):
                raise InvalidSignoffError(
                    "Human sign-off role must identify a qualified lawyer."
                )

        qualification = normalized.get("qualified_lawyer")
        if qualification is not None:
            if isinstance(qualification, bool):
                qualified = qualification
            elif isinstance(qualification, str):
                qualified = qualification.strip().lower() in (
                    _AFFIRMATIVE_QUALIFICATIONS
                )
            else:
                qualified = False
            if not qualified:
                raise InvalidSignoffError(
                    "Human sign-off must affirm qualified-lawyer status."
                )
            normalized["qualified_lawyer"] = True
        elif normalized_role not in _QUALIFIED_LAWYER_ROLES:
            raise InvalidSignoffError(
                "Human sign-off must affirm qualified-lawyer status."
            )

        signed_at = normalized.get("signed_at")
        if signed_at is None:
            signed_at = _utc_now()
        elif isinstance(signed_at, datetime):
            if signed_at.tzinfo is None:
                signed_at = signed_at.replace(tzinfo=timezone.utc)
            signed_at = signed_at.astimezone(timezone.utc).isoformat().replace(
                "+00:00",
                "Z",
            )
        normalized["signed_at"] = _validate_timestamp(
            signed_at,
            "signed_at",
        )
        return normalized

    def record_human_signoff(
        self,
        receipt_id: str,
        signoff: Mapping[str, Any] | Any,
    ) -> dict[str, Any]:
        """Append qualified-lawyer sign-off with ``actor=human`` tracking."""

        normalized_receipt_id = _require_identifier(receipt_id, "receipt_id")
        normalized_signoff = self._validate_human_signoff(signoff)
        signoff_hash = _sha256(normalized_signoff)
        signoff_signature = self._sign(
            "human-signoff",
            {
                "receipt_id": normalized_receipt_id,
                "signoff": normalized_signoff,
                "signoff_hash": signoff_hash,
            },
        )

        with self._transaction() as connection:
            receipt = self._receipt_row(connection, normalized_receipt_id)
            review_id = _require_identifier(
                receipt["review_id"],
                "review_id",
            )
            existing = connection.execute(
                "SELECT 1 FROM human_signoffs WHERE receipt_id = ?",
                (normalized_receipt_id,),
            ).fetchone()
            if existing is not None:
                raise InvalidSignoffError(
                    "Qualified-lawyer sign-off has already been recorded."
                )

            connection.execute(
                """
                INSERT INTO human_signoffs (
                    receipt_id,
                    review_id,
                    actor,
                    signer_id,
                    decision,
                    signed_at,
                    signoff_json,
                    signoff_hash,
                    signoff_signature
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    normalized_receipt_id,
                    review_id,
                    "human",
                    normalized_signoff["signer_id"],
                    normalized_signoff["decision"],
                    normalized_signoff["signed_at"],
                    canonical_json(normalized_signoff),
                    signoff_hash,
                    signoff_signature,
                ),
            )
            connection.execute(
                """
                UPDATE receipts
                SET status = ?,
                    human_sign_off_json = ?,
                    signed_at = ?,
                    human_signer_id = ?,
                    human_decision = ?
                WHERE receipt_id = ?
                """,
                (
                    _SIGNED_STATUS,
                    canonical_json(normalized_signoff),
                    normalized_signoff["signed_at"],
                    normalized_signoff["signer_id"],
                    normalized_signoff["decision"],
                    normalized_receipt_id,
                ),
            )

            self._append_audit_event(
                connection,
                receipt_id=normalized_receipt_id,
                review_id=review_id,
                event_type="human_sign_off",
                actor="human",
                event_data={
                    "receipt_id": normalized_receipt_id,
                    "review_id": review_id,
                    "signer_id": normalized_signoff["signer_id"],
                    "decision": normalized_signoff["decision"],
                    "signed_at": normalized_signoff["signed_at"],
                    "qualified_lawyer": normalized_signoff.get(
                        "qualified_lawyer",
                        True,
                    ),
                    "signoff_hash": signoff_hash,
                },
                created_at=normalized_signoff["signed_at"],
            )

        return self.get_receipt(normalized_receipt_id)

    def record_human_sign_off(
        self,
        receipt_id: str,
        signoff: Mapping[str, Any] | Any,
    ) -> dict[str, Any]:
        """Spelling-compatible alias for :meth:`record_human_signoff`."""

        return self.record_human_signoff(receipt_id, signoff)

    def sign_receipt(
        self,
        receipt_id: str,
        signoff: Mapping[str, Any] | None = None,
        **fields: object,
    ) -> dict[str, Any]:
        """Record human sign-off from a mapping or explicit keyword fields."""

        if signoff is not None and fields:
            raise TypeError(
                "Provide either signoff or individual sign-off fields, not both."
            )
        payload: dict[str, object] = (
            dict(signoff) if signoff is not None else {}
        )
        payload.update(fields)
        payload.setdefault("actor", "human")
        return self.record_human_signoff(receipt_id, payload)

    def _verify_receipt_row(
        self,
        connection: sqlite3.Connection,
        row: sqlite3.Row,
    ) -> bool:
        try:
            payload = self._stored_payload(row)
            required_values = {
                "receipt_id": row["receipt_id"],
                "review_id": row["review_id"],
                "created_at": row["created_at"],
                "contract_hash": row["contract_hash"],
                "playbook_hash": row["playbook_hash"],
                "receipt_hash": row["receipt_hash"],
            }
            for field, stored_value in required_values.items():
                if payload.get(field) != stored_value:
                    return False

            if payload.get("status") != _AWAITING_SIGNOFF_STATUS:
                return False
            if _require_hash(payload["contract_hash"], "contract_hash") != row[
                "contract_hash"
            ]:
                return False
            if _require_hash(payload["playbook_hash"], "playbook_hash") != row[
                "playbook_hash"
            ]:
                return False
            if _require_hash(payload["receipt_hash"], "receipt_hash") != row[
                "receipt_hash"
            ]:
                return False

            expected_signature = row["receipt_signature"]
            if expected_signature:
                unsigned = dict(payload)
                unsigned.pop("receipt_signature", None)
                calculated = self._sign("receipt", unsigned)
                if calculated is None or not hmac.compare_digest(
                    calculated,
                    expected_signature,
                ):
                    return False
            elif self._signing_key is not None:
                return False

            signoff = self._signoff_for_row(
                connection,
                row["receipt_id"],
            )
            if signoff is not None:
                signoff_row = connection.execute(
                    """
                    SELECT signoff_hash, signoff_signature, signoff_json
                    FROM human_signoffs
                    WHERE receipt_id = ?
                    """,
                    (row["receipt_id"],),
                ).fetchone()
                if signoff_row is None:
                    return False
                stored_signoff = _decode_json(
                    signoff_row["signoff_json"],
                    None,
                )
                if not isinstance(stored_signoff, dict):
                    return False
                if _sha256(stored_signoff) != signoff_row["signoff_hash"]:
                    return False
                expected_signoff_signature = signoff_row["signoff_signature"]
                if expected_signoff_signature:
                    calculated = self._sign(
                        "human-signoff",
                        {
                            "receipt_id": row["receipt_id"],
                            "signoff": stored_signoff,
                            "signoff_hash": signoff_row["signoff_hash"],
                        },
                    )
                    if calculated is None or not hmac.compare_digest(
                        calculated,
                        expected_signoff_signature,
                    ):
                        return False
                elif self._signing_key is not None:
                    return False
                if row["status"] != _SIGNED_STATUS:
                    return False
            elif row["status"] != _AWAITING_SIGNOFF_STATUS:
                return False

            return True
        except (StorageError, TypeError, ValueError, KeyError):
            return False

    def verify_receipt(self, receipt_id: str) -> bool:
        """Return whether a receipt's payload and signatures are intact."""

        normalized_receipt_id = _require_identifier(receipt_id, "receipt_id")
        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?",
                (normalized_receipt_id,),
            ).fetchone()
            return row is not None and self._verify_receipt_row(
                connection,
                row,
            )

    def _verify_event_rows(
        self,
        receipt_id: str,
        events: list[dict[str, Any]],
    ) -> bool:
        try:
            with self._lock:
                connection = self._require_connection()
                receipt = self._receipt_row(connection, receipt_id)
                if not self._verify_receipt_row(connection, receipt):
                    return False
                review_id = _require_identifier(
                    receipt["review_id"],
                    "review_id",
                )

            if not events:
                return False
            previous_hash = _GENESIS_HASH
            seen_ids: set[str] = set()

            for expected_sequence, event in enumerate(events, start=1):
                event_id = _require_identifier(event["event_id"], "event_id")
                if event_id in seen_ids:
                    return False
                seen_ids.add(event_id)

                if event["receipt_id"] != receipt_id:
                    return False
                if event["review_id"] != review_id:
                    return False
                if event["sequence_no"] != expected_sequence:
                    return False
                if event["previous_hash"] != previous_hash:
                    return False
                if _SHA256_RE.fullmatch(event["event_hash"] or "") is None:
                    return False
                if _SHA256_RE.fullmatch(event["previous_hash"] or "") is None:
                    return False

                material = self._event_material(
                    event_id=event_id,
                    receipt_id=receipt_id,
                    review_id=review_id,
                    sequence_no=expected_sequence,
                    event_type=_require_identifier(
                        event["event_type"],
                        "event_type",
                    ),
                    actor=_require_identifier(event["actor"], "actor"),
                    event_data=_normalize_object(
                        event["event_data"],
                        description="Audit event data",
                    ),
                    created_at=_validate_timestamp(
                        event["created_at"],
                        "created_at",
                    ),
                    previous_hash=event["previous_hash"],
                )
                if not hmac.compare_digest(
                    _sha256(material),
                    event["event_hash"],
                ):
                    return False

                signature = event.get("event_signature")
                if signature:
                    calculated = self._sign(
                        "audit-event",
                        {
                            "event": material,
                            "event_hash": event["event_hash"],
                        },
                    )
                    if calculated is None or not hmac.compare_digest(
                        calculated,
                        signature,
                    ):
                        return False
                elif self._signing_key is not None:
                    return False

                previous_hash = event["event_hash"]

            return True
        except (
            AuditChainError,
            ReceiptNotFoundError,
            StorageError,
            TypeError,
            ValueError,
            KeyError,
        ):
            return False

    def verify_audit_chain(
        self,
        receipt_id: str,
        *,
        raise_on_error: bool = True,
    ) -> bool:
        """Verify event ordering, hashes, receipt integrity, and HMACs."""

        normalized_receipt_id = _require_identifier(receipt_id, "receipt_id")
        try:
            events = self.get_audit_events(normalized_receipt_id)
        except ReceiptNotFoundError:
            if raise_on_error:
                raise
            return False

        if self._verify_event_rows(normalized_receipt_id, events):
            return True
        if raise_on_error:
            raise AuditChainError(
                f"Audit chain verification failed for {normalized_receipt_id!r}."
            )
        return False

    def healthcheck(self) -> bool:
        """Return whether SQLite, required columns, and indexes are usable."""

        try:
            with self._lock:
                connection = self._require_connection()
                quick_check = connection.execute(
                    "PRAGMA quick_check"
                ).fetchone()
                if quick_check is None or quick_check[0] != "ok":
                    return False
                if "review_id" not in _table_columns(
                    connection,
                    "audit_events",
                ):
                    return False
                if "payload_json" not in _table_columns(
                    connection,
                    "receipts",
                ):
                    return False
                index_names = {
                    row[1]
                    for row in connection.execute(
                        "PRAGMA index_list(audit_events)"
                    )
                }
                return (
                    "clausewindow_audit_receipt_created_idx"
                    in index_names
                )
        except (StorageError, sqlite3.Error):
            return False

    def close(self) -> None:
        """Close the SQLite connection. Repeated calls are safe."""

        with self._lock:
            if self._connection is not None and not self._closed:
                try:
                    self._connection.commit()
                finally:
                    self._connection.close()
            self._connection = None
            self._closed = True

    def __enter__(self) -> ReceiptStore:
        self._require_connection()
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


__all__ = [
    "AuditChainError",
    "DEFAULT_DATABASE_PATH",
    "InvalidSignoffError",
    "ReceiptConflictError",
    "ReceiptNotFoundError",
    "ReceiptStore",
    "SIGNING_KEY_ENV",
    "StorageError",
    "canonical_json",
]