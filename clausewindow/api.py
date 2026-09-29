"""FastAPI application for whole-document contract review and audit receipts.

Contract and playbook uploads are treated as untrusted input. The complete
contract is reviewed without retrieval chunking. All API responses retain the
constitutional decision-support disclaimer, and persisted receipts remain
awaiting qualified-lawyer sign-off.
"""

from __future__ import annotations

import hashlib
import json
import logging
import math
import os
import sys
import threading
from collections.abc import Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import asdict, dataclass, is_dataclass
from datetime import date, datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import UUID

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile as StarletteUploadFile

from .pdf_engine import (
    DEFAULT_MAX_DOCUMENT_BYTES,
    DEFAULT_MAX_DOCUMENT_CHARACTERS,
    DEFAULT_MAX_PDF_PAGES,
    DocumentError,
    DocumentExtractionError,
    DocumentTooLargeError,
    UnsupportedDocumentError,
    ingest_bytes,
)
from .playbook_engine import (
    DEFAULT_MAX_PLAYBOOK_BYTES,
    PlaybookEngine,
    PlaybookLoadError,
    PlaybookReview,
    load_playbook,
)
from .policy import CONSTITUTIONAL_RULE
from .storage import (
    ReceiptConflictError,
    ReceiptNotFoundError,
    ReceiptStore,
    StorageError,
    canonical_json,
)


LOGGER = logging.getLogger("clausewindow.api")
API_PREFIX = "/api/v1"
SERVICE_NAME = "clausewindow"
VERSION = "0.1.0"
DISCLAIMER = CONSTITUTIONAL_RULE

_MULTIPART_OVERHEAD_BYTES = 2 * 1024 * 1024
_UPLOAD_READ_SIZE = 64 * 1024

_CONTRACT_ALIASES = (
    "contract",
    "contract_file",
    "contract_upload",
    "agreement",
    "agreement_file",
    "document",
    "document_file",
)
_PLAYBOOK_ALIASES = (
    "playbook",
    "playbook_file",
    "playbook_upload",
    "policy",
    "policy_file",
    "rules",
    "rules_file",
)

_FALLBACK_TEMPLATE = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="color-scheme" content="dark">
  <title>ClauseWindow — Not Legal Advice</title>
  <style>
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding-top: 76px;
      background: #020617;
      color: #e2e8f0;
      font: 16px/1.5 system-ui, sans-serif;
    }
    .constitutional-banner {
      position: fixed;
      inset: 0 0 auto;
      z-index: 1000;
      min-height: 76px;
      display: flex;
      align-items: center;
      justify-content: center;
      padding: 14px 24px;
      background: #991b1b;
      border-bottom: 1px solid #ef4444;
      color: white;
      text-align: center;
      font-weight: 800;
    }
    main {
      width: min(900px, calc(100% - 32px));
      margin: 32px auto;
      padding: 24px;
      border: 1px solid #334155;
      border-radius: 14px;
      background: #0f172a;
    }
    label, input, button {
      display: block;
      width: 100%;
      margin: 12px 0;
      padding: 12px;
    }
    input {
      color: #e2e8f0;
      background: #1e293b;
      border: 1px dashed #64748b;
      border-radius: 8px;
    }
    button {
      border: 0;
      border-radius: 8px;
      background: #0284c7;
      color: white;
      font: inherit;
      font-weight: 800;
      cursor: pointer;
    }
    pre {
      overflow: auto;
      padding: 16px;
      border-radius: 8px;
      background: #020617;
      white-space: pre-wrap;
    }
  </style>
</head>
<body>
  <div class="constitutional-banner">
    Not Legal Advice — Decision support only. A qualified lawyer must sign.
  </div>
  <main>
    <h1>ClauseWindow</h1>
    <p>{{ disclaimer }}</p>
    <form id="review-form">
      <label>
        Contract PDF or text
        <input name="contract" type="file" required>
      </label>
      <label>
        JSON or YAML playbook
        <input name="playbook" type="file" required>
      </label>
      <button type="submit">Review complete document</button>
    </form>
    <pre id="result" aria-live="polite"></pre>
  </main>
  <script>
    const form = document.getElementById("review-form");
    const result = document.getElementById("result");

    form.addEventListener("submit", async (event) => {
      event.preventDefault();
      result.textContent = "Reviewing complete document…";

      try {
        const response = await fetch("{{ api_prefix }}/review", {
          method: "POST",
          body: new FormData(form)
        });
        const payload = await response.json();
        result.textContent = JSON.stringify(payload, null, 2);
      } catch (error) {
        result.textContent = "The review request could not be completed.";
      }
    });
  </script>
</body>
</html>
"""


@dataclass(frozen=True, slots=True)
class _Limits:
    """Configured resource limits for one application instance."""

    max_document_bytes: int
    max_document_characters: int
    max_pdf_pages: int
    max_playbook_bytes: int
    max_request_bytes: int


def _json_safe(value: Any) -> Any:
    """Convert supported domain values into JSON-compatible values."""

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
    if hasattr(value, "model_dump"):
        return _json_safe(value.model_dump(mode="json", by_alias=False))
    if is_dataclass(value):
        return _json_safe(asdict(value))
    if isinstance(value, Mapping):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, set):
        return [_json_safe(item) for item in sorted(value, key=str)]
    if isinstance(value, Sequence) and not isinstance(
        value, (str, bytes, bytearray)
    ):
        return [_json_safe(item) for item in value]
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("API values must not contain non-finite numbers.")
    return value


def _http_error(
    status_code: int,
    *,
    code: str,
    message: str,
    headers: Mapping[str, str] | None = None,
) -> HTTPException:
    """Construct a consistent HTTP API error."""

    return HTTPException(
        status_code=status_code,
        detail={"code": code, "message": message},
        headers=dict(headers or {}),
    )


def _find_template_directory(explicit: str | Path | None) -> Path | None:
    """Locate the operator-console template in source or installed layouts."""

    if explicit is not None:
        candidate = Path(explicit).expanduser().resolve()
        return candidate if candidate.is_dir() else None

    candidates = (
        Path(__file__).resolve().parents[1] / "web" / "templates",
        Path(sys.prefix)
        / "share"
        / "clausewindow"
        / "web"
        / "templates",
    )
    for candidate in candidates:
        if candidate.is_dir():
            return candidate
    return None


def _database_setting(
    database_path: str | Path | None,
    db_path: str | Path | None,
) -> str | Path:
    """Resolve the receipt database without treating ``:memory:`` as a path."""

    if database_path is not None and db_path is not None:
        raise ValueError("Pass either database_path or db_path, not both.")

    selected = database_path or db_path
    if selected is None:
        selected = os.environ.get("CLAUSEWINDOW_DB", "receipts.db")

    if isinstance(selected, str) and selected == ":memory:":
        return selected

    path = Path(selected).expanduser()
    if not path.is_absolute():
        path = Path.cwd() / path
    return path.resolve()


def _document_payload(review: PlaybookReview) -> dict[str, Any]:
    """Create a non-vectorized public description of the complete document."""

    document = review.document
    metadata = _json_safe(getattr(document, "metadata", {}))
    clauses = getattr(document, "clauses", [])
    text = getattr(document, "text", "")

    return {
        "filename": getattr(document, "filename", None),
        "media_type": getattr(document, "media_type", None),
        "sha256": document.sha256,
        "byte_count": getattr(document, "byte_count", None),
        "character_count": getattr(document, "character_count", len(text)),
        "page_count": getattr(document, "page_count", None),
        "benchmark_id": getattr(document, "benchmark_id", None),
        "clause_count": len(clauses),
        "chunking": "none",
        "vector_chunking": False,
        "offsets_basis": "unicode_code_points",
        "metadata": metadata,
    }


def _playbook_payload(review: PlaybookReview) -> dict[str, Any]:
    """Return canonical playbook identity and snapshot information."""

    playbook = review.playbook
    return {
        "playbook_id": getattr(playbook, "playbook_id", None),
        "name": getattr(playbook, "name", None),
        "version": getattr(playbook, "version", None),
        "sha256": playbook.sha256,
        "rule_count": getattr(playbook, "rule_count", None),
        "constitutional_rule": getattr(
            playbook, "constitutional_rule", CONSTITUTIONAL_RULE
        ),
        "snapshot": _json_safe(playbook.immutable_snapshot()),
    }


def _receipt_payload(
    review: PlaybookReview,
    *,
    filename: str,
) -> dict[str, Any]:
    """Build the immutable receipt submitted to SQLite storage."""

    document_payload = _document_payload(review)
    findings = _json_safe(list(review.findings))
    redlines = _json_safe(list(review.redlines))

    unsigned: dict[str, Any] = {
        "receipt_id": review.review_id,
        "review_id": review.review_id,
        "status": review.status,
        "created_at": _json_safe(review.created_at),
        "contract_hash": review.document.sha256,
        "playbook_hash": review.playbook.sha256,
        "findings": findings,
        "redlines": redlines,
        "human_sign_off": None,
        "playbook_snapshot": _json_safe(
            review.playbook.immutable_snapshot()
        ),
        "metadata": {
            "service": SERVICE_NAME,
            "version": VERSION,
            "filename": filename,
            "media_type": document_payload["media_type"],
            "byte_count": document_payload["byte_count"],
            "character_count": document_payload["character_count"],
            "page_count": document_payload["page_count"],
            "clause_count": document_payload["clause_count"],
            "chunking": "none",
            "offsets_basis": "unicode_code_points",
            "api_endpoint": f"{API_PREFIX}/review",
        },
    }
    unsigned["receipt_hash"] = hashlib.sha256(
        canonical_json(unsigned).encode("utf-8")
    ).hexdigest()
    return unsigned


def _receipt_summary(store: ReceiptStore, receipt_id: str) -> dict[str, Any]:
    """Load and JSON-normalize one persisted receipt."""

    return _json_safe(store.get_receipt(receipt_id))


def _fallback_receipt_listing(
    store: ReceiptStore,
    *,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """List receipts using the stable schema if no public list helper exists."""

    connection = store._require_connection()
    total = int(
        connection.execute("SELECT COUNT(*) FROM receipts").fetchone()[0]
    )
    rows = connection.execute(
        """
        SELECT receipt_id
        FROM receipts
        ORDER BY created_at DESC, receipt_id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    ).fetchall()
    receipts = [store.get_receipt(row[0]) for row in rows]
    return {"receipts": receipts, "total": total}


def _list_receipts(
    store: ReceiptStore,
    *,
    limit: int,
    offset: int,
) -> dict[str, Any]:
    """Normalize receipt-list results across supported store return shapes."""

    list_method = getattr(store, "list_receipts", None)
    if not callable(list_method):
        return _fallback_receipt_listing(
            store, limit=limit, offset=offset
        )

    try:
        result = list_method(limit=limit, offset=offset)
    except TypeError:
        result = list_method(limit, offset)

    receipts: Any
    total: int | None = None

    if isinstance(result, Mapping):
        receipts = (
            result.get("receipts")
            if "receipts" in result
            else result.get("items", result.get("data", []))
        )
        for total_key in ("total", "total_count", "count"):
            candidate = result.get(total_key)
            if isinstance(candidate, int):
                total = candidate
                break
    elif (
        isinstance(result, tuple)
        and len(result) == 2
        and isinstance(result[1], int)
    ):
        receipts, total = result
    else:
        receipts = result

    receipt_list = list(receipts or [])
    if total is None:
        count_method = getattr(store, "count_receipts", None)
        if callable(count_method):
            counted = count_method()
            if isinstance(counted, int):
                total = counted
            elif isinstance(counted, Mapping):
                candidate = counted.get("total")
                if isinstance(candidate, int):
                    total = candidate

    if total is None:
        try:
            connection = store._require_connection()
            total = int(
                connection.execute(
                    "SELECT COUNT(*) FROM receipts"
                ).fetchone()[0]
            )
        except (AttributeError, StorageError, sqlite_error_types()):
            total = len(receipt_list)

    return {
        "receipts": _json_safe(receipt_list),
        "total": total,
        "limit": limit,
        "offset": offset,
    }


def sqlite_error_types() -> tuple[type[BaseException], ...]:
    """Return SQLite exception types without making sqlite a public API type."""

    import sqlite3

    return (sqlite3.Error,)


async def _read_limited_upload(
    upload: StarletteUploadFile,
    *,
    field_name: str,
    max_bytes: int,
) -> bytes:
    """Read one multipart upload while enforcing a hard byte limit."""

    announced_size = getattr(upload, "size", None)
    if isinstance(announced_size, int) and announced_size > max_bytes:
        raise _http_error(
            413,
            code=f"{field_name}_too_large",
            message=(
                f"The {field_name} upload exceeds the configured "
                f"{max_bytes}-byte limit."
            ),
        )

    chunks: list[bytes] = []
    byte_count = 0

    try:
        while True:
            chunk = await upload.read(_UPLOAD_READ_SIZE)
            if not chunk:
                break

            byte_count += len(chunk)
            if byte_count > max_bytes:
                raise _http_error(
                    413,
                    code=f"{field_name}_too_large",
                    message=(
                        f"The {field_name} upload exceeds the configured "
                        f"{max_bytes}-byte limit."
                    ),
                )
            chunks.append(chunk)
    finally:
        await upload.close()

    content = b"".join(chunks)
    if not content:
        raise _http_error(
            400,
            code=f"empty_{field_name}",
            message=f"The {field_name} upload is empty.",
        )
    return content


def _upload_from_form(
    form: Mapping[str, Any],
    aliases: Sequence[str],
    *,
    field_name: str,
) -> StarletteUploadFile:
    """Resolve an uploaded file while supporting conventional field aliases."""

    for alias in aliases:
        candidate = form.get(alias)
        if isinstance(candidate, StarletteUploadFile):
            return candidate
        if (
            candidate is not None
            and hasattr(candidate, "read")
            and hasattr(candidate, "filename")
        ):
            return candidate  # type: ignore[return-value]

    raise _http_error(
        422,
        code="missing_upload",
        message=(
            f"A multipart {field_name} file is required. "
            f"Accepted field names: {', '.join(aliases)}."
        ),
    )


async def _extract_multipart_uploads(
    request: Request,
    limits: _Limits,
) -> tuple[
    StarletteUploadFile,
    bytes,
    str,
    StarletteUploadFile,
    bytes,
    str,
]:
    """Parse and bound both multipart uploads before document processing."""

    content_type = request.headers.get("content-type", "").lower()
    if "multipart/form-data" not in content_type:
        raise _http_error(
            415,
            code="multipart_required",
            message=(
                "The review endpoint requires a multipart/form-data request "
                "containing contract and playbook files."
            ),
        )

    try:
        form = await request.form(max_files=4, max_fields=12)
    except HTTPException:
        raise
    except Exception as exc:
        raise _http_error(
            400,
            code="invalid_multipart",
            message="The multipart request could not be parsed.",
        ) from exc

    try:
        contract_upload = _upload_from_form(
            form, _CONTRACT_ALIASES, field_name="contract"
        )
        playbook_upload = _upload_from_form(
            form, _PLAYBOOK_ALIASES, field_name="playbook"
        )

        contract_bytes = await _read_limited_upload(
            contract_upload,
            field_name="contract",
            max_bytes=limits.max_document_bytes,
        )
        playbook_bytes = await _read_limited_upload(
            playbook_upload,
            field_name="playbook",
            max_bytes=limits.max_playbook_bytes,
        )

        contract_filename = (
            Path(contract_upload.filename or "contract.txt").name
        )
        playbook_filename = (
            Path(playbook_upload.filename or "playbook.json").name
        )

        return (
            contract_upload,
            contract_bytes,
            contract_filename,
            playbook_upload,
            playbook_bytes,
            playbook_filename,
        )
    finally:
        close = getattr(form, "close", None)
        if callable(close):
            result = close()
            if hasattr(result, "__await__"):
                await result


def create_app(
    database_path: str | Path | None = None,
    *,
    db_path: str | Path | None = None,
    template_directory: str | Path | None = None,
    template_path: str | Path | None = None,
    max_document_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES,
    max_document_characters: int = DEFAULT_MAX_DOCUMENT_CHARACTERS,
    max_pdf_pages: int = DEFAULT_MAX_PDF_PAGES,
    max_playbook_bytes: int = DEFAULT_MAX_PLAYBOOK_BYTES,
) -> FastAPI:
    """Create a configured ClauseWindow FastAPI application.

    Args:
        database_path: SQLite receipt database path.
        db_path: Alias for ``database_path``.
        template_directory: Directory containing ``index.html``.
        template_path: Alias for ``template_directory``.
        max_document_bytes: Maximum uploaded contract size.
        max_document_characters: Maximum extracted contract characters.
        max_pdf_pages: Maximum accepted PDF page count.
        max_playbook_bytes: Maximum uploaded playbook size.

    Returns:
        A configured FastAPI application.
    """

    if template_directory is not None and template_path is not None:
        raise ValueError(
            "Pass either template_directory or template_path, not both."
        )

    numeric_limits = {
        "max_document_bytes": max_document_bytes,
        "max_document_characters": max_document_characters,
        "max_pdf_pages": max_pdf_pages,
        "max_playbook_bytes": max_playbook_bytes,
    }
    for name, value in numeric_limits.items():
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise ValueError(f"{name} must be a positive integer.")

    selected_template = template_directory or template_path
    limits = _Limits(
        max_document_bytes=max_document_bytes,
        max_document_characters=max_document_characters,
        max_pdf_pages=max_pdf_pages,
        max_playbook_bytes=max_playbook_bytes,
        max_request_bytes=(
            max_document_bytes
            + max_playbook_bytes
            + _MULTIPART_OVERHEAD_BYTES
        ),
    )
    database_setting = _database_setting(database_path, db_path)

    if database_setting != ":memory:":
        Path(database_setting).parent.mkdir(parents=True, exist_ok=True)

    resolved_template_directory = _find_template_directory(
        selected_template
    )
    templates = (
        Jinja2Templates(directory=str(resolved_template_directory))
        if resolved_template_directory is not None
        else None
    )

    @asynccontextmanager
    async def lifespan(application: FastAPI):
        previous_store = getattr(
            application.state, "receipt_store", None
        )
        if previous_store is not None:
            previous_store.close()

        store = ReceiptStore(database_setting)
        application.state.receipt_store = store
        try:
            yield
        finally:
            if getattr(application.state, "receipt_store", None) is store:
                store.close()
                application.state.receipt_store = None

    application = FastAPI(
        title="ClauseWindow Contract Review API",
        version=VERSION,
        description=DISCLAIMER,
        lifespan=lifespan,
    )
    application.state.receipt_store = None
    application.state.receipt_store_lock = threading.Lock()
    application.state.playbook_engine = PlaybookEngine()
    application.state.limits = limits
    application.state.database_setting = database_setting

    def get_store() -> ReceiptStore:
        store = getattr(application.state, "receipt_store", None)
        if store is not None:
            return store

        lock: threading.Lock = application.state.receipt_store_lock
        with lock:
            store = getattr(application.state, "receipt_store", None)
            if store is None:
                store = ReceiptStore(database_setting)
                application.state.receipt_store = store
        return store

    @application.middleware("http")
    async def security_and_resource_headers(
        request: Request,
        call_next,
    ):
        content_length = request.headers.get("content-length")
        if content_length is not None:
            try:
                declared_size = int(content_length)
            except ValueError as exc:
                raise _http_error(
                    400,
                    code="invalid_content_length",
                    message="The Content-Length header is invalid.",
                ) from exc

            if declared_size < 0:
                raise _http_error(
                    400,
                    code="invalid_content_length",
                    message="The Content-Length header is invalid.",
                )
            if declared_size > limits.max_request_bytes:
                raise _http_error(
                    413,
                    code="request_too_large",
                    message=(
                        "The complete request exceeds the configured "
                        f"{limits.max_request_bytes}-byte limit."
                    ),
                )

        response = await call_next(request)
        response.headers.setdefault("Cache-Control", "no-store")
        response.headers.setdefault("Pragma", "no-cache")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        response.headers.setdefault(
            "X-ClauseWindow-Not-Legal-Advice", "true"
        )
        return response

    @application.get("/", response_class=HTMLResponse)
    async def operator_console(request: Request):
        context = {
            "service": SERVICE_NAME,
            "version": VERSION,
            "disclaimer": DISCLAIMER,
            "constitutional_rule": DISCLAIMER,
            "not_legal_advice": True,
            "api_prefix": API_PREFIX,
        }
        if templates is not None and (
            resolved_template_directory / "index.html"
        ).is_file():
            return templates.TemplateResponse(
                request=request,
                name="index.html",
                context=context,
            )

        fallback = _FALLBACK_TEMPLATE.replace(
            "{{ disclaimer }}", DISCLAIMER
        ).replace("{{ api_prefix }}", API_PREFIX)
        return HTMLResponse(content=fallback)

    @application.get("/health")
    async def health():
        store = get_store()
        healthy = await run_in_threadpool(store.healthcheck)
        if not healthy:
            return JSONResponse(
                status_code=503,
                content={
                    "status": "unhealthy",
                    "service": SERVICE_NAME,
                    "version": VERSION,
                    "database": "unavailable",
                    "not_legal_advice": True,
                    "constitutional_rule": DISCLAIMER,
                },
            )

        return {
            "status": "ok",
            "service": SERVICE_NAME,
            "version": VERSION,
            "database": "ok",
            "not_legal_advice": True,
            "constitutional_rule": DISCLAIMER,
        }

    @application.post(f"{API_PREFIX}/review")
    async def review_document(request: Request):
        (
            _contract_upload,
            contract_bytes,
            contract_filename,
            _playbook_upload,
            playbook_bytes,
            playbook_filename,
        ) = await _extract_multipart_uploads(request, limits)

        contract_media_type = (
            _contract_upload.content_type
            or "application/octet-stream"
        )

        try:
            document = await run_in_threadpool(
                ingest_bytes,
                contract_bytes,
                filename=contract_filename,
                media_type=contract_media_type,
                max_document_bytes=limits.max_document_bytes,
                max_document_characters=(
                    limits.max_document_characters
                ),
                max_pdf_pages=limits.max_pdf_pages,
            )
        except DocumentTooLargeError as exc:
            raise _http_error(
                413,
                code="document_too_large",
                message=str(exc),
            ) from exc
        except UnsupportedDocumentError as exc:
            raise _http_error(
                415,
                code="unsupported_document",
                message=str(exc),
            ) from exc
        except DocumentExtractionError as exc:
            raise _http_error(
                400,
                code="document_extraction_failed",
                message=str(exc),
            ) from exc
        except DocumentError as exc:
            raise _http_error(
                400,
                code="invalid_document",
                message=str(exc),
            ) from exc

        try:
            playbook = await run_in_threadpool(
                load_playbook,
                playbook_bytes,
                filename=playbook_filename,
            )
        except PlaybookLoadError as exc:
            raise _http_error(
                400,
                code="invalid_playbook",
                message=str(exc),
            ) from exc

        try:
            reviewed_document = await run_in_threadpool(
                application.state.playbook_engine.review,
                document,
                playbook,
            )
        except PlaybookLoadError as exc:
            raise _http_error(
                400,
                code="playbook_review_failed",
                message=str(exc),
            ) from exc

        receipt_payload = _receipt_payload(
            reviewed_document,
            filename=contract_filename,
        )
        store = get_store()

        try:
            await run_in_threadpool(
                store.save_receipt,
                receipt_payload,
            )
        except ReceiptConflictError as exc:
            raise _http_error(
                409,
                code="receipt_conflict",
                message="The review receipt already exists.",
            ) from exc
        except StorageError as exc:
            LOGGER.exception("Could not persist ClauseWindow review receipt")
            raise _http_error(
                500,
                code="receipt_persistence_failed",
                message=(
                    "The review completed, but its audit receipt could not "
                    "be persisted."
                ),
            ) from exc

        try:
            persisted_receipt = await run_in_threadpool(
                _receipt_summary,
                store,
                reviewed_document.review_id,
            )
        except ReceiptNotFoundError as exc:
            raise _http_error(
                500,
                code="receipt_readback_failed",
                message=(
                    "The receipt was persisted but could not be read back."
                ),
            ) from exc

        try:
            audit_chain_valid = await run_in_threadpool(
                store.verify_audit_chain,
                reviewed_document.review_id,
            )
        except (AttributeError, StorageError):
            audit_chain_valid = None

        document_payload = _document_payload(reviewed_document)
        playbook_payload = _playbook_payload(reviewed_document)
        findings = _json_safe(list(reviewed_document.findings))
        redlines = _json_safe(list(reviewed_document.redlines))

        return {
            "schema_version": "1.0",
            "review_id": reviewed_document.review_id,
            "receipt_id": reviewed_document.review_id,
            "status": reviewed_document.status,
            "action": reviewed_document.action.value,
            "risk_score": float(reviewed_document.risk_score),
            "created_at": _json_safe(reviewed_document.created_at),
            "not_legal_advice": True,
            "constitutional_rule": DISCLAIMER,
            "qualified_lawyer_signoff_required": True,
            "engine": "deterministic_whole_document",
            "contract_hash": document.sha256,
            "playbook_hash": playbook.sha256,
            "document": document_payload,
            "playbook": playbook_payload,
            "findings": findings,
            "redlines": redlines,
            "redlines_json": redlines,
            "redlines_filename": "redlines.json",
            "audit_chain_valid": audit_chain_valid,
            "receipt": persisted_receipt,
        }

    @application.get(f"{API_PREFIX}/receipts")
    async def list_receipts(
        limit: int = Query(default=50, ge=1, le=200),
        offset: int = Query(default=0, ge=0),
    ):
        store = get_store()
        try:
            result = await run_in_threadpool(
                _list_receipts,
                store,
                limit=limit,
                offset=offset,
            )
        except StorageError as exc:
            LOGGER.exception("Could not list ClauseWindow receipts")
            raise _http_error(
                503,
                code="receipt_storage_unavailable",
                message="Receipt storage is temporarily unavailable.",
            ) from exc

        return {
            **result,
            "not_legal_advice": True,
            "constitutional_rule": DISCLAIMER,
        }

    @application.get(f"{API_PREFIX}/receipts/{{receipt_id}}")
    async def get_receipt(receipt_id: str):
        store = get_store()
        try:
            receipt = await run_in_threadpool(
                _receipt_summary,
                store,
                receipt_id,
            )
        except ReceiptNotFoundError as exc:
            raise _http_error(
                404,
                code="receipt_not_found",
                message="The requested receipt does not exist.",
            ) from exc
        except StorageError as exc:
            raise _http_error(
                503,
                code="receipt_storage_unavailable",
                message="Receipt storage is temporarily unavailable.",
            ) from exc

        return {
            "receipt": receipt,
            "not_legal_advice": True,
            "constitutional_rule": DISCLAIMER,
        }

    return application


app = create_app()


__all__ = ["API_PREFIX", "app", "create_app"]