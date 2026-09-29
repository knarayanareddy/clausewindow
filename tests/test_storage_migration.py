import sqlite3

from clausewindow.storage import ReceiptStore


def test_legacy_schema_is_migrated_before_dependent_indexes(tmp_path):
    database = tmp_path / "legacy-receipts.db"

    connection = sqlite3.connect(database)
    connection.executescript(
        """
        CREATE TABLE receipts (
            receipt_id TEXT PRIMARY KEY,
            status TEXT NOT NULL,
            created_at TEXT NOT NULL,
            contract_hash TEXT NOT NULL,
            playbook_hash TEXT NOT NULL,
            receipt_hash TEXT NOT NULL
        );

        CREATE TABLE audit_events (
            event_id TEXT PRIMARY KEY,
            receipt_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            actor TEXT NOT NULL,
            event_data_json TEXT NOT NULL,
            created_at TEXT NOT NULL,
            previous_hash TEXT NOT NULL,
            event_hash TEXT NOT NULL
        );
        """
    )
    connection.close()

    store = ReceiptStore(database)
    try:
        receipt_columns = {
            row[1]
            for row in store._require_connection().execute(
                "PRAGMA table_info(receipts)"
            )
        }
        audit_columns = {
            row[1]
            for row in store._require_connection().execute(
                "PRAGMA table_info(audit_events)"
            )
        }
        indexes = {
            row[1]
            for row in store._require_connection().execute(
                "PRAGMA index_list(audit_events)"
            )
        }

        assert "review_id" in receipt_columns
        assert "payload_json" in receipt_columns
        assert "review_id" in audit_columns
        assert "clausewindow_audit_receipt_created_idx" in indexes

        store.save_receipt(
            {
                "receipt_id": "migrated-receipt",
                "review_id": "migrated-review",
                "status": "awaiting_qualified_lawyer_signoff",
                "created_at": "2025-01-01T00:00:00Z",
                "contract_hash": "a" * 64,
                "playbook_hash": "b" * 64,
                "receipt_hash": "c" * 64,
                "findings": [],
                "redlines": [],
                "human_sign_off": None,
            }
        )

        assert store.healthcheck() is True
        assert store.get_receipt("migrated-receipt")["review_id"] == (
            "migrated-review"
        )
        assert store.verify_audit_chain("migrated-receipt") is True
    finally:
        store.close()