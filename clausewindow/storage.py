"""SQLite-backed immutable receipts and hash-chained audit events."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import sqlite3
import threading
from collections.abc import Mapping
from dataclasses import asdict, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID, uuid4


class StorageError(RuntimeError):
    """Base receipt-storage failure."""


class ReceiptNotFoundError(StorageError):
    """Raised when a receipt identifier does not exist."""


class ReceiptConflictError(StorageError):
    """Raised when an immutable receipt identifier is reused."""


class InvalidSignoffError(StorageError):
    """Raised when qualified-lawyer sign-off is invalid or duplicated."""


class AuditChainError(StorageError):
    """Raised when an audit event cannot be recorded safely."""


_GENESIS_HASH = "0" * 64
_SIGNABLE_DECISIONS = frozenset(
    {"approved", "rejected", "revision_requested"}
)
_AWAITING_SIGNOFF_STATUS = "awaiting_qualified_lawyer_signoff"
_SIGNED_STATUS = "qualified_lawyer_signed"
_REQUIRED_RECEIPT_FIELDS = (
    "receipt_id",
    "review_id",
    "status",
    "created_at",
    "contract_hash",
    "playbook_hash",
    "receipt_hash",
)
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
        return value.model_dump(mode="json")
    message = (
        f"Value of type {type(value).__name__} is not JSON serializable."
    )
    raise TypeError(message)


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


def _normalize_payload(value: Mapping[str, Any] | Any) -> dict[str, Any]:
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


def _require_identifier(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field_name} must be a string.")
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{field_name} must not be blank.")
    if len(normalized) > 200:
        raise ValueError(f"{field_name} must not exceed 200 characters.")
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


class ReceiptStore:
    """Persist immutable review receipts and their audit chains.

    Schema setup is intentionally migration-safe. In particular, columns are
    added and inspected before indexes are created. Older ClauseWindow
    databases did not contain ``audit_events.review_id`` even though an older
    initializer attempted to index that column immediately.
    """

    def __init__(
        self,
        database_path: str | os.PathLike[str] = "receipts.db",
    ) -> None:
        raw_path = os.fspath(database_path)
        self._lock = threading.RLock()
        self._connection: sqlite3.Connection | None = None
        self._closed = False

        if raw_path == ":memory:":
            resolved_path = raw_path
        else:
            path = Path(raw_path).expanduser()
            path.parent.mkdir(parents=True, exist_ok=True)
            resolved_path = str(path)

        self.database_path = resolved_path

        try:
            self._connection = sqlite3.connect(
                resolved_path,
                timeout=30.0,
                check_same_thread=False,
                isolation_level="",
            )
            self._connection.row_factory = sqlite3.Row
            self._connection.execute("PRAGMA foreign_keys = ON")
            self._connection.execute("PRAGMA busy_timeout = 30000")
            self._connection.execute("PRAGMA journal_mode = WAL")
            self._connection.execute("PRAGMA synchronous = FULL")
            self._initialize_schema()
        except Exception as exc:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            raise StorageError(
                "Unable to initialize the receipt database."
            ) from exc

    def _initialize_schema(self) -> None:
        connection = self._require_connection()

        # Do not create indexes in this script. Existing databases may have
        # older table definitions, and CREATE INDEX does not add missing
        # columns to an existing table.
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS receipts (
                receipt_id TEXT PRIMARY KEY,
                review_id TEXT NOT NULL,
                status TEXT NOT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT,
                contract_hash TEXT NOT NULL,
                playbook_hash TEXT NOT NULL,
                receipt_hash TEXT NOT NULL,
                payload_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                receipt_id TEXT NOT NULL,
                review_id TEXT NOT NULL,
                event_type TEXT NOT NULL,
                actor TEXT NOT NULL,
                event_data_json TEXT NOT NULL,
                created_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                FOREIGN KEY (receipt_id)
                    REFERENCES receipts(receipt_id)
                    ON DELETE RESTRICT
            );
            """
        )

        expected_columns = {
            "receipts": (
                ("receipt_id", "TEXT NOT NULL DEFAULT ''"),
                ("review_id", "TEXT NOT NULL DEFAULT ''"),
                ("status", "TEXT NOT NULL DEFAULT ''"),
                ("created_at", "TEXT NOT NULL DEFAULT ''"),
                ("updated_at", "TEXT"),
                ("contract_hash", "TEXT NOT NULL DEFAULT ''"),
                ("playbook_hash", "TEXT NOT NULL DEFAULT ''"),
                ("receipt_hash", "TEXT NOT NULL DEFAULT ''"),
                ("payload_json", "TEXT NOT NULL DEFAULT '{}'"),
            ),
            "audit_events": (
                ("event_id", "TEXT NOT NULL DEFAULT ''"),
                ("receipt_id", "TEXT NOT NULL DEFAULT ''"),
                ("review_id", "TEXT NOT NULL DEFAULT ''"),
                ("event_type", "TEXT NOT NULL DEFAULT ''"),
                ("actor", "TEXT NOT NULL DEFAULT 'system'"),
                ("event_data_json", "TEXT NOT NULL DEFAULT '{}'"),
                ("created_at", "TEXT NOT NULL DEFAULT ''"),
                ("previous_hash", f"TEXT NOT NULL DEFAULT '{_GENESIS_HASH}'"),
                ("event_hash", "TEXT NOT NULL DEFAULT ''"),
            ),
        }

        # This must happen before any index references review_id.
        for table, columns in expected_columns.items():
            existing = self._table_info(table)
            for column, definition in columns:
                if column not in existing:
                    connection.execute(
                        f"ALTER TABLE {table} ADD COLUMN "
                        f"{column} {definition}"
                    )

        # CREATE INDEX IF NOT EXISTS is safe only after the migration above.
        connection.executescript(
            """
            CREATE INDEX IF NOT EXISTS
                clausewindow_receipts_review_id_idx
            ON receipts(review_id);

            CREATE INDEX IF NOT EXISTS
                clausewindow_audit_receipt_created_idx
            ON audit_events(receipt_id, created_at);
            """
        )
        connection.commit()

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise StorageError("The receipt store is closed.")
        return self._connection

    def _table_info(self, table: str) -> dict[str, sqlite3.Row]:
        if table not in {"receipts", "audit_events"}:
            raise ValueError("Unsupported receipt-store table.")
        connection = self._require_connection()
        rows = connection.execute(
            f"PRAGMA table_info({table})"
        ).fetchall()
        return {str(row["name"]): row for row in rows}

    def _receipt_payload_columns(self) -> tuple[str, ...]:
        columns = self._table_info("receipts")
        return tuple(
            column
            for column in _RECEIPT_PAYLOAD_COLUMNS
            if column in columns
        )

    def _receipt_insert_values(
        self,
        receipt: Mapping[str, Any],
    ) -> dict[str, object]:
        table_info = self._table_info("receipts")
        serialized = canonical_json(receipt)
        values: dict[str, object] = {
            "receipt_id": receipt["receipt_id"],
            "review_id": receipt["review_id"],
            "status": receipt["status"],
            "created_at": receipt["created_at"],
            "updated_at": receipt.get("updated_at"),
            "contract_hash": receipt["contract_hash"],
            "playbook_hash": receipt["playbook_hash"],
            "receipt_hash": receipt["receipt_hash"],
        }

        for column in self._receipt_payload_columns():
            values[column] = serialized

        for column, field_name in _RECEIPT_FIELD_JSON_COLUMNS.items():
            if column in table_info:
                values[column] = canonical_json(receipt.get(field_name))

        for column, metadata in table_info.items():
            if column in values:
                continue
            if not metadata["notnull"] or metadata["dflt_value"] is not None:
                continue
            if column in receipt:
                value = receipt[column]
                values[column] = (
                    serialized
                    if isinstance(value, (dict, list))
                    else value
                )
                continue
            raise StorageError(
                f"Existing receipts table requires unmapped column "
                f"{column!r}; migrate the database before opening it."
            )

        return values

    def _insert_receipt_row(
        self,
        receipt: Mapping[str, Any],
    ) -> None:
        connection = self._require_connection()
        values = self._receipt_insert_values(receipt)
        columns = tuple(values)
        placeholders = ", ".join("?" for _ in columns)
        assignments = ", ".join(f"{column} = ?" for column in columns)
        connection.execute(
            f"INSERT INTO receipts ({', '.join(columns)}) "
            f"VALUES ({placeholders})",
            tuple(values[column] for column in columns),
        )
        _ = assignments

    def _receipt_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        receipt: dict[str, Any] = {}
        row_keys = set(row.keys())

        for column in self._receipt_payload_columns():
            if column not in row_keys:
                continue
            candidate = _decode_json(row[column], {})
            if isinstance(candidate, dict) and len(candidate) >= len(receipt):
                receipt = candidate

        for field_name in (
            "receipt_id",
            "review_id",
            "status",
            "created_at",
            "updated_at",
            "contract_hash",
            "playbook_hash",
            "receipt_hash",
        ):
            if field_name in row_keys and row[field_name] not in (None, ""):
                receipt[field_name] = row[field_name]

        table_info = self._table_info("receipts")
        for column, field_name in _RECEIPT_FIELD_JSON_COLUMNS.items():
            if column in table_info and column in row_keys:
                default: object = [] if field_name in {"findings", "redlines"} else None
                receipt[field_name] = _decode_json(row[column], default)

        receipt.setdefault("human_sign_off", None)
        return receipt

    def _receipt_exists(self, receipt_id: str) -> bool:
        connection = self._require_connection()
        row = connection.execute(
            "SELECT 1 FROM receipts WHERE receipt_id = ? LIMIT 1",
            (receipt_id,),
        ).fetchone()
        return row is not None

    def _event_hash_material(
        self,
        *,
        event_id: str,
        receipt_id: str,
        event_type: str,
        actor: str,
        event_data: object,
        created_at: str,
        previous_hash: str,
    ) -> dict[str, object]:
        return {
            "event_id": event_id,
            "receipt_id": receipt_id,
            "event_type": event_type,
            "actor": actor,
            "event_data": event_data,
            "created_at": created_at,
            "previous_hash": previous_hash,
        }

    def _event_from_row(self, row: sqlite3.Row) -> dict[str, Any]:
        event_data = _decode_json(row["event_data_json"], {})
        return {
            "sequence": int(row["_sequence"]),
            "event_id": str(row["event_id"]),
            "receipt_id": str(row["receipt_id"]),
            "review_id": str(row["review_id"]),
            "event_type": str(row["event_type"]),
            "actor": str(row["actor"]),
            "event_data": event_data,
            "created_at": str(row["created_at"]),
            "previous_hash": str(row["previous_hash"]),
            "event_hash": str(row["event_hash"]),
        }

    def _audit_event_columns(self) -> dict[str, sqlite3.Row]:
        return self._table_info("audit_events")

    def _insert_audit_event(
        self,
        *,
        receipt_id: str,
        review_id: str,
        event_type: str,
        actor: str,
        event_data: Mapping[str, object],
        created_at: str,
        actor_type: str = "system",
    ) -> str:
        connection = self._require_connection()
        previous_row = connection.execute(
            """
            SELECT event_hash
            FROM audit_events
            WHERE receipt_id = ?
            ORDER BY rowid DESC
            LIMIT 1
            """,
            (receipt_id,),
        ).fetchone()
        previous_hash = (
            str(previous_row["event_hash"])
            if previous_row is not None
            else _GENESIS_HASH
        )

        event_id = str(uuid4())
        serialized_event = canonical_json(event_data)
        event_hash = _sha256(
            self._event_hash_material(
                event_id=event_id,
                receipt_id=receipt_id,
                event_type=event_type,
                actor=actor,
                event_data=event_data,
                created_at=created_at,
                previous_hash=previous_hash,
            )
        )

        table_info = self._audit_event_columns()
        values: dict[str, object] = {
            "event_id": event_id,
            "receipt_id": receipt_id,
            "review_id": review_id,
            "event_type": event_type,
            "actor": actor,
            "event_data_json": serialized_event,
            "created_at": created_at,
            "previous_hash": previous_hash,
            "event_hash": event_hash,
            "actor_type": actor_type,
            "actor_id": actor,
            "event_timestamp": created_at,
            "previous_event_hash": previous_hash,
        }

        for column in _AUDIT_PAYLOAD_COLUMNS:
            if column in table_info:
                values[column] = serialized_event

        for column, metadata in table_info.items():
            if column in values:
                continue
            if not metadata["notnull"] or metadata["dflt_value"] is not None:
                continue
            raise StorageError(
                f"Existing audit_events table requires unmapped column "
                f"{column!r}; migrate the database before opening it."
            )

        insert_values = {
            column: value
            for column, value in values.items()
            if column in table_info
        }
        columns = tuple(insert_values)
        placeholders = ", ".join("?" for _ in columns)
        connection.execute(
            f"INSERT INTO audit_events ({', '.join(columns)}) "
            f"VALUES ({placeholders})",
            tuple(insert_values[column] for column in columns),
        )
        return event_id

    def _update_receipt_row(
        self,
        receipt: Mapping[str, Any],
    ) -> None:
        connection = self._require_connection()
        table_info = self._table_info("receipts")
        assignments: dict[str, object] = {
            "status": receipt["status"],
            "updated_at": receipt.get("updated_at"),
            "receipt_hash": receipt["receipt_hash"],
        }

        for column in self._receipt_payload_columns():
            assignments[column] = canonical_json(receipt)

        for column, field_name in _RECEIPT_FIELD_JSON_COLUMNS.items():
            if column in table_info:
                assignments[column] = canonical_json(
                    receipt.get(field_name)
                )

        available = {
            column: value
            for column, value in assignments.items()
            if column in table_info
        }
        update_clause = ", ".join(
            f"{column} = ?" for column in available
        )
        parameters = tuple(available.values()) + (
            receipt["receipt_id"],
        )
        cursor = connection.execute(
            f"UPDATE receipts SET {update_clause} "
            "WHERE receipt_id = ?",
            parameters,
        )
        if cursor.rowcount != 1:
            raise ReceiptNotFoundError(
                f"Receipt {receipt['receipt_id']!r} does not exist."
            )

    @staticmethod
    def _calculate_receipt_hash(receipt: Mapping[str, Any]) -> str:
        material = {
            key: value
            for key, value in receipt.items()
            if key not in {"receipt_hash", "audit_valid"}
        }
        return _sha256(material)

    def save_receipt(
        self,
        receipt: Mapping[str, Any] | object,
    ) -> dict[str, Any]:
        """Persist a new immutable receipt and its genesis audit event."""

        try:
            normalized = _normalize_payload(receipt)
        except ValueError as exc:
            raise StorageError(str(exc)) from exc

        missing = [
            field
            for field in _REQUIRED_RECEIPT_FIELDS
            if field not in normalized
        ]
        if missing:
            raise StorageError(
                "Receipt is missing required fields: "
                + ", ".join(missing)
            )

        try:
            normalized["receipt_id"] = _require_identifier(
                normalized["receipt_id"],
                "receipt_id",
            )
            normalized["review_id"] = _require_identifier(
                normalized["review_id"],
                "review_id",
            )
        except ValueError as exc:
            raise StorageError(str(exc)) from exc

        normalized.setdefault("human_sign_off", None)

        with self._lock:
            connection = self._require_connection()
            if self._receipt_exists(normalized["receipt_id"]):
                raise ReceiptConflictError(
                    f"Receipt {normalized['receipt_id']!r} already exists."
                )

            created_at = str(normalized["created_at"] or _utc_now())
            normalized["created_at"] = created_at

            try:
                with connection:
                    self._insert_receipt_row(normalized)
                    self._insert_audit_event(
                        receipt_id=str(normalized["receipt_id"]),
                        review_id=str(normalized["review_id"]),
                        event_type="receipt_created",
                        actor="clausewindow",
                        event_data={
                            "status": normalized["status"],
                            "contract_hash": normalized["contract_hash"],
                            "playbook_hash": normalized["playbook_hash"],
                            "receipt_hash": normalized["receipt_hash"],
                        },
                        created_at=created_at,
                        actor_type="system",
                    )
            except sqlite3.IntegrityError as exc:
                if self._receipt_exists(str(normalized["receipt_id"])):
                    raise ReceiptConflictError(
                        f"Receipt {normalized['receipt_id']!r} already exists."
                    ) from exc
                raise StorageError(
                    "Unable to persist the receipt."
                ) from exc

        return dict(normalized)

    def get_receipt(self, receipt_id: str) -> dict[str, Any]:
        """Return a receipt without internal database bookkeeping fields."""

        normalized_id = _require_identifier(receipt_id, "receipt_id")
        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:
                raise ReceiptNotFoundError(
                    f"Receipt {normalized_id!r} does not exist."
                )
            return self._receipt_from_row(row)

    def list_receipts(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> list[dict[str, Any]]:
        """List newest receipts first."""

        if isinstance(limit, bool) or not isinstance(limit, int):
            raise ValueError("limit must be an integer.")
        if isinstance(offset, bool) or not isinstance(offset, int):
            raise ValueError("offset must be an integer.")
        if not 1 <= limit <= 1_000:
            raise ValueError("limit must be between 1 and 1000.")
        if offset < 0:
            raise ValueError("offset must not be negative.")

        with self._lock:
            connection = self._require_connection()
            rows = connection.execute(
                """
                SELECT *
                FROM receipts
                ORDER BY created_at DESC, receipt_id DESC
                LIMIT ? OFFSET ?
                """,
                (limit, offset),
            ).fetchall()
            return [self._receipt_from_row(row) for row in rows]

    def count_receipts(self) -> int:
        """Return the total number of persisted receipts."""

        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                "SELECT COUNT(*) AS receipt_count FROM receipts"
            ).fetchone()
            return int(row["receipt_count"])

    def get_audit_events(self, receipt_id: str) -> list[dict[str, Any]]:
        """Return the receipt's audit events in append order."""

        normalized_id = _require_identifier(receipt_id, "receipt_id")
        with self._lock:
            connection = self._require_connection()
            if not self._receipt_exists(normalized_id):
                raise ReceiptNotFoundError(
                    f"Receipt {normalized_id!r} does not exist."
                )

            rows = connection.execute(
                """
                SELECT rowid AS _sequence, *
                FROM audit_events
                WHERE receipt_id = ?
                ORDER BY rowid ASC
                """,
                (normalized_id,),
            ).fetchall()
            return [self._event_from_row(row) for row in rows]

    def verify_audit_chain(
        self,
        receipt_id: str,
        *,
        raise_on_error: bool = False,
    ) -> bool:
        """Verify event hashes and links for one receipt.

        Integrity failures return ``False`` by default. Callers that need an
        exception can request ``raise_on_error=True``.
        """

        normalized_id = _require_identifier(receipt_id, "receipt_id")

        with self._lock:
            connection = self._require_connection()
            if not self._receipt_exists(normalized_id):
                raise ReceiptNotFoundError(
                    f"Receipt {normalized_id!r} does not exist."
                )

            rows = connection.execute(
                """
                SELECT rowid AS _sequence, *
                FROM audit_events
                WHERE receipt_id = ?
                ORDER BY rowid ASC
                """,
                (normalized_id,),
            ).fetchall()

            if not rows:
                if raise_on_error:
                    raise AuditChainError(
                        f"Receipt {normalized_id!r} has no audit events."
                    )
                return False

            previous_hash = _GENESIS_HASH
            for row in rows:
                try:
                    event = self._event_from_row(row)
                except StorageError as exc:
                    if raise_on_error:
                        raise AuditChainError(
                            f"Receipt {normalized_id!r} contains malformed "
                            "audit data."
                        ) from exc
                    return False

                if event["receipt_id"] != normalized_id:
                    if raise_on_error:
                        raise AuditChainError(
                            "Audit event receipt_id does not match its "
                            "receipt."
                        )
                    return False

                if not hmac.compare_digest(
                    str(event["previous_hash"]).lower(),
                    previous_hash.lower(),
                ):
                    if raise_on_error:
                        raise AuditChainError(
                            f"Broken previous-hash link at audit event "
                            f"{event['event_id']!r}."
                        )
                    return False

                expected_hash = _sha256(
                    self._event_hash_material(
                        event_id=str(event["event_id"]),
                        receipt_id=normalized_id,
                        event_type=str(event["event_type"]),
                        actor=str(event["actor"]),
                        event_data=event["event_data"],
                        created_at=str(event["created_at"]),
                        previous_hash=str(event["previous_hash"]),
                    )
                )

                if not hmac.compare_digest(
                    str(event["event_hash"]).lower(),
                    expected_hash,
                ):
                    if raise_on_error:
                        raise AuditChainError(
                            f"Audit event {event['event_id']!r} failed its "
                            "SHA-256 integrity check."
                        )
                    return False

                previous_hash = expected_hash

            return True

    def sign_receipt(
        self,
        receipt_id: str,
        *,
        actor: str,
        decision: str,
        qualified_lawyer_attestation: bool,
        professional_identifier: str | None = None,
        note: str | None = None,
    ) -> dict[str, Any]:
        """Apply an immutable, human qualified-lawyer sign-off."""

        normalized_id = _require_identifier(receipt_id, "receipt_id")

        if qualified_lawyer_attestation is not True:
            raise InvalidSignoffError(
                "A qualified-lawyer attestation is required; automated "
                "output cannot sign this receipt."
            )

        if not isinstance(actor, str) or not actor.strip():
            raise InvalidSignoffError(
                "A qualified lawyer must be identified as the signing actor."
            )
        normalized_actor = actor.strip()
        if len(normalized_actor) > 200:
            raise InvalidSignoffError(
                "The signing actor must not exceed 200 characters."
            )

        if decision not in _SIGNABLE_DECISIONS:
            raise InvalidSignoffError(
                "Unsupported qualified-lawyer decision."
            )

        if professional_identifier is not None:
            if not isinstance(professional_identifier, str):
                raise InvalidSignoffError(
                    "The professional identifier must be text."
                )
            professional_identifier = professional_identifier.strip()
            if not professional_identifier:
                raise InvalidSignoffError(
                    "The professional identifier must not be blank."
                )
            if len(professional_identifier) > 300:
                raise InvalidSignoffError(
                    "The professional identifier must not exceed 300 "
                    "characters."
                )

        if note is not None:
            if not isinstance(note, str):
                raise InvalidSignoffError("The sign-off note must be text.")
            if len(note) > 4_000:
                raise InvalidSignoffError(
                    "The sign-off note must not exceed 4000 characters."
                )

        with self._lock:
            connection = self._require_connection()
            row = connection.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?",
                (normalized_id,),
            ).fetchone()
            if row is None:
                raise ReceiptNotFoundError(
                    f"Receipt {normalized_id!r} does not exist."
                )

            if not self.verify_audit_chain(normalized_id):
                raise AuditChainError(
                    "The receipt cannot be signed because its audit chain "
                    "is invalid."
                )

            receipt = self._receipt_from_row(row)
            if (
                receipt.get("status") != _AWAITING_SIGNOFF_STATUS
                or receipt.get("human_sign_off") is not None
            ):
                raise InvalidSignoffError(
                    f"Receipt {normalized_id!r} has already been signed or "
                    "is not eligible for sign-off."
                )

            signed_at = _utc_now()
            previous_receipt_hash = str(receipt["receipt_hash"])
            signature_material = {
                "receipt_id": normalized_id,
                "review_id": str(receipt["review_id"]),
                "previous_receipt_hash": previous_receipt_hash,
                "actor": normalized_actor,
                "actor_type": "human_qualified_lawyer",
                "decision": decision,
                "qualified_lawyer_attestation": True,
                "professional_identifier": professional_identifier,
                "note": note,
                "signed_at": signed_at,
            }
            human_sign_off = {
                **signature_material,
                "signature": "sha256:" + _sha256(signature_material),
            }

            receipt["status"] = _SIGNED_STATUS
            receipt["updated_at"] = signed_at
            receipt["signed_at"] = signed_at
            receipt["human_sign_off"] = human_sign_off
            receipt["receipt_hash"] = self._calculate_receipt_hash(receipt)

            try:
                with connection:
                    self._update_receipt_row(receipt)
                    self._insert_audit_event(
                        receipt_id=normalized_id,
                        review_id=str(receipt["review_id"]),
                        event_type="receipt_signed",
                        actor=normalized_actor,
                        event_data={
                            "decision": decision,
                            "previous_receipt_hash": previous_receipt_hash,
                            "receipt_hash": receipt["receipt_hash"],
                            "human_sign_off": human_sign_off,
                        },
                        created_at=signed_at,
                        actor_type="human_qualified_lawyer",
                    )
            except (ReceiptNotFoundError, AuditChainError):
                raise
            except sqlite3.Error as exc:
                raise StorageError(
                    "Unable to atomically sign the receipt."
                ) from exc

            signed_row = connection.execute(
                "SELECT * FROM receipts WHERE receipt_id = ?",
                (normalized_id,),
            ).fetchone()
            if signed_row is None:
                raise StorageError(
                    "The signed receipt could not be reloaded."
                )
            return self._receipt_from_row(signed_row)

    def healthcheck(self) -> bool:
        """Return whether SQLite and the required tables are available."""

        with self._lock:
            try:
                connection = self._require_connection()
                connection.execute("SELECT 1").fetchone()
                tables = {
                    str(row["name"])
                    for row in connection.execute(
                        """
                        SELECT name
                        FROM sqlite_master
                        WHERE type = 'table'
                        """
                    ).fetchall()
                }
                return {
                    "receipts",
                    "audit_events",
                }.issubset(tables)
            except (StorageError, sqlite3.Error):
                return False

    def close(self) -> None:
        """Close the SQLite connection. Repeated calls are safe."""

        with self._lock:
            if self._connection is not None:
                self._connection.close()
                self._connection = None
            self._closed = True

    def __enter__(self) -> ReceiptStore:
        self._require_connection()
        return self

    def __exit__(
        self,
        exc_type: object,
        exc_value: object,
        traceback: object,
    ) -> None:
        self.close()