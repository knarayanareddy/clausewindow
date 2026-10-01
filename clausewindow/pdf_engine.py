"""Bounded, whole-document PDF and plain-text ingestion.

The complete extracted document is retained as one text object. Page spans are
provenance metadata only; they are not retrieval chunks. No vectorization,
embedding, or retrieval chunking is performed.

This module provides decision-support ingestion only. It does not provide
legal advice. A qualified lawyer must review the output and sign the final
decision.
"""

from __future__ import annotations

import hashlib
import operator
from collections.abc import Mapping
from dataclasses import dataclass, replace
from io import BytesIO
from pathlib import Path, PurePath
from typing import Any, BinaryIO, Final

try:
    from pypdf import PdfReader as _PdfReader
except ImportError:  # pragma: no cover - dependency-free installations
    _PdfReader = None


DEFAULT_MAX_DOCUMENT_BYTES: Final[int] = 50 * 1024 * 1024
DEFAULT_MAX_DOCUMENT_CHARACTERS: Final[int] = 20_000_000
DEFAULT_MAX_PDF_PAGES: Final[int] = 1_000

_PDF_HEADER: Final[bytes] = b"%PDF-"
_PDF_HEADER_SEARCH_WINDOW: Final[int] = 1_024
_UTF8_BOM: Final[bytes] = b"\xef\xbb\xbf"
_UTF16_LE_BOM: Final[bytes] = b"\xff\xfe"
_UTF16_BE_BOM: Final[bytes] = b"\xfe\xff"

_PDF_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {
        "application/pdf",
        "application/x-pdf",
        "application/acrobat",
        "applications/vnd.pdf",
        "text/pdf",
    }
)
_TEXT_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {
        "text/plain",
        "text/markdown",
        "text/csv",
        "application/json",
        "application/yaml",
        "application/x-yaml",
        "text/yaml",
        "text/x-yaml",
    }
)
_GENERIC_BINARY_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {
        "application/octet-stream",
        "application/binary",
        "binary/octet-stream",
    }
)
_TEXT_SUFFIXES: Final[dict[str, str]] = {
    ".csv": "text/csv",
    ".json": "application/json",
    ".md": "text/markdown",
    ".markdown": "text/markdown",
    ".txt": "text/plain",
    ".text": "text/plain",
    ".yaml": "application/yaml",
    ".yml": "application/yaml",
}


class DocumentError(ValueError):
    """Base class for document-ingestion failures."""


class UnsupportedDocumentError(DocumentError):
    """Raised when an upload is not supported PDF or plain-text data."""


class DocumentExtractionError(DocumentError):
    """Raised when a supported document cannot be safely extracted."""


class EmptyDocumentError(DocumentExtractionError):
    """Raised when a supported document has no extractable text."""


class DocumentTooLargeError(DocumentExtractionError):
    """Raised when a document exceeds a configured resource limit."""

    def __init__(
        self,
        message: str,
        *,
        limit: int,
        actual: int | None = None,
    ) -> None:
        super().__init__(message)
        self.limit = limit
        self.actual = actual


@dataclass(frozen=True, slots=True)
class DocumentLimits:
    """Validated limits applied to every ingestion operation."""

    max_document_bytes: int = DEFAULT_MAX_DOCUMENT_BYTES
    max_document_characters: int = DEFAULT_MAX_DOCUMENT_CHARACTERS
    max_pdf_pages: int = DEFAULT_MAX_PDF_PAGES

    def __post_init__(self) -> None:
        _require_positive_limit(
            "max_document_bytes",
            self.max_document_bytes,
        )
        _require_positive_limit(
            "max_document_characters",
            self.max_document_characters,
        )
        _require_positive_limit("max_pdf_pages", self.max_pdf_pages)


@dataclass(frozen=True, slots=True)
class PageSpan:
    """A page's half-open span in the complete extracted document."""

    page_number: int
    start_offset: int
    end_offset: int

    @property
    def offsets(self) -> tuple[int, int]:
        return self.start_offset, self.end_offset

    @property
    def char_count(self) -> int:
        return self.end_offset - self.start_offset

    def to_dict(self) -> dict[str, int]:
        return {
            "page_number": self.page_number,
            "start_offset": self.start_offset,
            "end_offset": self.end_offset,
        }

    def __getitem__(self, key: str) -> int:
        if key == "page_number":
            return self.page_number
        if key == "start_offset":
            return self.start_offset
        if key == "end_offset":
            return self.end_offset
        raise KeyError(key)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, PageSpan):
            return (
                self.page_number == other.page_number
                and self.start_offset == other.start_offset
                and self.end_offset == other.end_offset
            )
        if isinstance(other, Mapping):
            return self.to_dict() == dict(other)
        if isinstance(other, tuple):
            return (self.page_number, self.start_offset, self.end_offset) == other
        return NotImplemented

    def __hash__(self) -> int:
        return hash((self.page_number, self.start_offset, self.end_offset))


@dataclass(frozen=True, slots=True)
class IngestedDocument:
    """The complete text and provenance for one ingested document."""

    text: str
    sha256: str
    source_name: str
    media_type: str
    source_format: str
    page_count: int | None
    page_spans: tuple[PageSpan, ...]
    metadata: dict[str, object]

    @property
    def content(self) -> str:
        """Return the complete unbroken document text."""

        return self.text

    @property
    def full_text(self) -> str:
        return self.text

    @property
    def content_hash(self) -> str:
        return self.sha256

    @property
    def content_sha256(self) -> str:
        return self.sha256

    @property
    def document_sha256(self) -> str:
        return self.sha256

    @property
    def char_count(self) -> int:
        return len(self.text)

    @property
    def filename(self) -> str:
        return self.source_name

    @property
    def is_pdf(self) -> bool:
        return self.source_format == "pdf"

    @property
    def page_offsets(self) -> tuple[tuple[int, int], ...]:
        return tuple(span.offsets for span in self.page_spans)

    def to_dict(self) -> dict[str, object]:
        return {
            "text": self.text,
            "sha256": self.sha256,
            "source_name": self.source_name,
            "media_type": self.media_type,
            "source_format": self.source_format,
            "page_count": self.page_count,
            "page_spans": [span.to_dict() for span in self.page_spans],
            "char_count": self.char_count,
            "metadata": dict(self.metadata),
        }


# Compatibility aliases for callers that use extraction-oriented names.
ExtractedDocument = IngestedDocument
Document = IngestedDocument


class DocumentIngestor:
    """Extract complete PDF and text documents under fixed resource limits."""

    def __init__(
        self,
        limits: DocumentLimits | Mapping[str, int] | None = None,
        *,
        max_document_bytes: int | None = None,
        max_document_characters: int | None = None,
        max_pdf_pages: int | None = None,
        reader_factory: Any | None = None,
    ) -> None:
        values: dict[str, int] = {
            "max_document_bytes": DEFAULT_MAX_DOCUMENT_BYTES,
            "max_document_characters": DEFAULT_MAX_DOCUMENT_CHARACTERS,
            "max_pdf_pages": DEFAULT_MAX_PDF_PAGES,
        }
        if isinstance(limits, DocumentLimits):
            values = {
                "max_document_bytes": limits.max_document_bytes,
                "max_document_characters": limits.max_document_characters,
                "max_pdf_pages": limits.max_pdf_pages,
            }
        elif limits is not None:
            if not isinstance(limits, Mapping):
                raise TypeError("limits must be a DocumentLimits or mapping.")
            values.update(
                {
                    key: limits[key]
                    for key in values
                    if key in limits
                }
            )

        if max_document_bytes is not None:
            values["max_document_bytes"] = max_document_bytes
        if max_document_characters is not None:
            values["max_document_characters"] = max_document_characters
        if max_pdf_pages is not None:
            values["max_pdf_pages"] = max_pdf_pages

        self.limits = DocumentLimits(**values)
        self._reader_factory = reader_factory

    def ingest_bytes(
        self,
        data: bytes | bytearray | memoryview,
        filename: str | Path | None = None,
        media_type: str | None = None,
    ) -> IngestedDocument:
        return _ingest_bytes(
            data,
            filename=filename,
            media_type=media_type,
            limits=self.limits,
            reader_factory=self._reader_factory,
        )

    def ingest_text(
        self,
        text: str,
        source_name: str | Path | None = None,
        media_type: str = "text/plain",
    ) -> IngestedDocument:
        return _ingest_text(
            text,
            source_name=source_name,
            media_type=media_type,
            limits=self.limits,
        )

    def ingest_pdf(
        self,
        data: bytes | bytearray | memoryview,
        filename: str | Path | None = None,
        media_type: str = "application/pdf",
    ) -> IngestedDocument:
        return _ingest_pdf(
            data,
            filename=filename,
            media_type=media_type,
            limits=self.limits,
            reader_factory=self._reader_factory,
        )

    def ingest_path(
        self,
        path: str | Path,
        media_type: str | None = None,
    ) -> IngestedDocument:
        return _ingest_path(
            path,
            media_type=media_type,
            limits=self.limits,
            reader_factory=self._reader_factory,
        )

    def extract_document(
        self,
        source: str | bytes | bytearray | memoryview | Path | BinaryIO,
        *,
        filename: str | Path | None = None,
        media_type: str | None = None,
    ) -> IngestedDocument:
        return _extract_document(
            source,
            filename=filename,
            media_type=media_type,
            limits=self.limits,
            reader_factory=self._reader_factory,
        )

    def extract_text(
        self,
        source: str | bytes | bytearray | memoryview | Path | BinaryIO,
        *,
        filename: str | Path | None = None,
        media_type: str | None = None,
    ) -> str:
        return self.extract_document(
            source,
            filename=filename,
            media_type=media_type,
        ).text


def _require_positive_limit(name: str, value: object) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{name} must be an integer, not a boolean.")
    try:
        normalized = operator.index(value)
    except TypeError as exc:
        raise TypeError(f"{name} must be an integer.") from exc
    if normalized <= 0:
        raise ValueError(f"{name} must be greater than zero.")
    return normalized


def _make_ingestor(
    limits: DocumentLimits | Mapping[str, int] | None,
    max_document_bytes: int | None,
    max_document_characters: int | None,
    max_pdf_pages: int | None,
) -> DocumentIngestor:
    return DocumentIngestor(
        limits,
        max_document_bytes=max_document_bytes,
        max_document_characters=max_document_characters,
        max_pdf_pages=max_pdf_pages,
    )


def _normalize_media_type(media_type: str | None) -> str | None:
    if media_type is None:
        return None
    if not isinstance(media_type, str):
        raise TypeError("media_type must be a string or None.")
    normalized = media_type.split(";", 1)[0].strip().lower()
    return normalized or None


def _media_type_parameters(media_type: str | None) -> dict[str, str]:
    if media_type is None or ";" not in media_type:
        return {}
    parameters: dict[str, str] = {}
    for component in media_type.split(";")[1:]:
        if "=" not in component:
            continue
        name, value = component.split("=", 1)
        normalized_name = name.strip().lower()
        normalized_value = value.strip()
        if normalized_value.startswith('"') and normalized_value.endswith('"'):
            normalized_value = normalized_value[1:-1]
        if normalized_name:
            parameters[normalized_name] = normalized_value
    return parameters


def _safe_source_name(
    filename: str | Path | None,
    *,
    default: str,
) -> str:
    if filename is None:
        return default
    if not isinstance(filename, (str, Path, PurePath)):
        raise TypeError("filename must be a string or path.")
    raw_name = str(filename).replace("\\", "/").rsplit("/", 1)[-1].strip()
    if not raw_name:
        return default
    if len(raw_name) > 255:
        raise ValueError("filename must not exceed 255 characters.")
    return raw_name


def _as_bytes(
    data: bytes | bytearray | memoryview,
    limits: DocumentLimits,
) -> bytes:
    try:
        view = memoryview(data)
    except TypeError as exc:
        raise TypeError("Document data must be bytes-like.") from exc

    actual_size = view.nbytes
    if actual_size > limits.max_document_bytes:
        raise DocumentTooLargeError(
            "Document exceeds the maximum byte size.",
            limit=limits.max_document_bytes,
            actual=actual_size,
        )
    return bytes(view)


def _normalize_newlines(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def _decode_text(
    data: bytes,
    *,
    media_type: str | None,
    unsupported_on_failure: bool,
) -> tuple[str, str]:
    if data.startswith(_UTF8_BOM):
        codec = "utf-8-sig"
    elif data.startswith(_UTF16_LE_BOM):
        codec = "utf-16-le"
    elif data.startswith(_UTF16_BE_BOM):
        codec = "utf-16-be"
    else:
        charset = _media_type_parameters(media_type).get("charset")
        codec = charset.strip() if charset and charset.strip() else "utf-8"
        try:
            "".encode(codec)
        except LookupError as exc:
            raise DocumentExtractionError(
                f"Unsupported text encoding: {codec!r}."
            ) from exc

    try:
        decoded = data.decode(codec, errors="strict")
    except (UnicodeDecodeError, UnicodeError) as exc:
        error_type = (
            UnsupportedDocumentError
            if unsupported_on_failure
            else DocumentExtractionError
        )
        raise error_type(
            "Text data is not valid in its declared character encoding."
        ) from exc

    if "\x00" in decoded:
        error_type = (
            UnsupportedDocumentError
            if unsupported_on_failure
            else DocumentExtractionError
        )
        raise error_type("Text data contains unsupported null bytes.")

    try:
        decoded.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DocumentExtractionError(
            "Text data contains invalid Unicode scalar values."
        ) from exc

    return _normalize_newlines(decoded), codec.lower()


def _text_document(
    text: str,
    *,
    source_name: str,
    media_type: str,
    encoding: str,
    limits: DocumentLimits,
) -> IngestedDocument:
    normalized = _normalize_newlines(text)
    if len(normalized) > limits.max_document_characters:
        raise DocumentTooLargeError(
            "Document exceeds the maximum character count.",
            limit=limits.max_document_characters,
            actual=len(normalized),
        )
    if not normalized.strip():
        raise EmptyDocumentError("Document contains no extractable text.")

    try:
        encoded = normalized.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise DocumentExtractionError(
            "Text contains invalid Unicode scalar values."
        ) from exc
    if len(encoded) > limits.max_document_bytes:
        raise DocumentTooLargeError(
            "Document exceeds the maximum byte size.",
            limit=limits.max_document_bytes,
            actual=len(encoded),
        )

    digest = hashlib.sha256(encoded).hexdigest()
    return IngestedDocument(
        text=normalized,
        sha256=digest,
        source_name=source_name,
        media_type=media_type,
        source_format="text",
        page_count=None,
        page_spans=(),
        metadata={
            "chunking": "disabled",
            "extraction_method": "plain-text",
            "encoding": encoding,
        },
    )


def _pdf_header_offset(data: bytes) -> int | None:
    offset = data[:_PDF_HEADER_SEARCH_WINDOW].find(_PDF_HEADER)
    return offset if offset >= 0 else None


def _extract_pdf(
    data: bytes,
    *,
    source_name: str,
    media_type: str,
    limits: DocumentLimits,
    reader_factory: Any | None,
) -> IngestedDocument:
    factory = reader_factory if reader_factory is not None else _PdfReader
    if factory is None:
        raise DocumentExtractionError(
            "PDF extraction requires the pypdf package."
        )

    try:
        reader = factory(BytesIO(data), strict=False)
    except Exception as exc:
        raise DocumentExtractionError("The PDF could not be parsed.") from exc

    encrypted = bool(getattr(reader, "is_encrypted", False))
    if encrypted:
        try:
            decrypt_result = reader.decrypt("")
        except Exception as exc:
            raise DocumentExtractionError(
                "The encrypted PDF could not be inspected."
            ) from exc
        if not decrypt_result:
            raise DocumentExtractionError(
                "The PDF is encrypted and cannot be opened without a password."
            )

    try:
        pages = reader.pages
        page_count = len(pages)
    except Exception as exc:
        raise DocumentExtractionError(
            "The PDF page collection could not be read."
        ) from exc

    if page_count <= 0:
        raise EmptyDocumentError("The PDF contains no pages.")
    if page_count > limits.max_pdf_pages:
        raise DocumentTooLargeError(
            "PDF exceeds the maximum page count.",
            limit=limits.max_pdf_pages,
            actual=page_count,
        )

    page_texts: list[str] = []
    page_spans: list[PageSpan] = []
    total_characters = max(0, page_count - 1)

    for page_index in range(page_count):
        try:
            page = pages[page_index]
            extracted = page.extract_text()
        except Exception as exc:
            raise DocumentExtractionError(
                f"Text extraction failed on PDF page {page_index + 1}."
            ) from exc

        if extracted is None:
            page_text = ""
        elif isinstance(extracted, str):
            page_text = _normalize_newlines(extracted)
        else:
            raise DocumentExtractionError(
                f"PDF page {page_index + 1} returned invalid text data."
            )

        try:
            page_text.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise DocumentExtractionError(
                f"PDF page {page_index + 1} contains invalid Unicode."
            ) from exc

        if "\x00" in page_text:
            raise DocumentExtractionError(
                f"PDF page {page_index + 1} contains unsupported null bytes."
            )

        total_characters += len(page_text)
        if total_characters > limits.max_document_characters:
            raise DocumentTooLargeError(
                "Document exceeds the maximum character count.",
                limit=limits.max_document_characters,
                actual=total_characters,
            )
        page_texts.append(page_text)

    start_offset = 0
    for page_index, page_text in enumerate(page_texts, start=1):
        end_offset = start_offset + len(page_text)
        page_spans.append(
            PageSpan(
                page_number=page_index,
                start_offset=start_offset,
                end_offset=end_offset,
            )
        )
        start_offset = end_offset
        if page_index < len(page_texts):
            start_offset += 1

    text = "\n".join(page_texts)
    if not text.strip():
        raise EmptyDocumentError("The PDF contains no extractable text.")

    encoded = text.encode("utf-8")
    if len(encoded) > limits.max_document_bytes:
        raise DocumentTooLargeError(
            "Document exceeds the maximum byte size.",
            limit=limits.max_document_bytes,
            actual=len(encoded),
        )

    return IngestedDocument(
        text=text,
        sha256=hashlib.sha256(encoded).hexdigest(),
        source_name=source_name,
        media_type=media_type,
        source_format="pdf",
        page_count=page_count,
        page_spans=tuple(page_spans),
        metadata={
            "chunking": "disabled",
            "extraction_method": "pypdf",
            "encrypted": encrypted,
            "page_count": page_count,
        },
    )


def _ingest_bytes(
    data: bytes | bytearray | memoryview,
    filename: str | Path | None = None,
    media_type: str | None = None,
    *,
    limits: DocumentLimits,
    reader_factory: Any | None = None,
) -> IngestedDocument:
    payload = _as_bytes(data, limits)
    normalized_media_type = _normalize_media_type(media_type)

    if normalized_media_type in _PDF_MEDIA_TYPES:
        return _extract_pdf(
            payload,
            source_name=_safe_source_name(filename, default="document.pdf"),
            media_type=normalized_media_type or "application/pdf",
            limits=limits,
            reader_factory=reader_factory,
        )

    if normalized_media_type in _TEXT_MEDIA_TYPES:
        text, encoding = _decode_text(
            payload,
            media_type=media_type,
            unsupported_on_failure=False,
        )
        return _text_document(
            text,
            source_name=_safe_source_name(filename, default="document.txt"),
            media_type=normalized_media_type,
            encoding=encoding,
            limits=limits,
        )

    if (
        normalized_media_type is not None
        and normalized_media_type not in _GENERIC_BINARY_MEDIA_TYPES
    ):
        raise UnsupportedDocumentError(
            f"Unsupported media type: {normalized_media_type!r}."
        )

    header_offset = _pdf_header_offset(payload)
    if header_offset is not None:
        return _extract_pdf(
            payload[header_offset:],
            source_name=_safe_source_name(filename, default="document.pdf"),
            media_type="application/pdf",
            limits=limits,
            reader_factory=reader_factory,
        )

    try:
        text, encoding = _decode_text(
            payload,
            media_type=media_type,
            unsupported_on_failure=True,
        )
    except DocumentExtractionError:
        raise UnsupportedDocumentError(
            "Document is neither a supported PDF nor UTF-8 plain text."
        ) from None

    return _text_document(
        text,
        source_name=_safe_source_name(filename, default="document.txt"),
        media_type="text/plain",
        encoding=encoding,
        limits=limits,
    )


def _ingest_text(
    text: str,
    source_name: str | Path | None = None,
    media_type: str = "text/plain",
    *,
    limits: DocumentLimits,
) -> IngestedDocument:
    if not isinstance(text, str):
        raise TypeError("text must be a string.")
    normalized_media_type = _normalize_media_type(media_type)
    if normalized_media_type not in _TEXT_MEDIA_TYPES:
        raise UnsupportedDocumentError(
            f"Unsupported text media type: {normalized_media_type!r}."
        )
    return _text_document(
        text,
        source_name=_safe_source_name(source_name, default="document.txt"),
        media_type=normalized_media_type or "text/plain",
        encoding="utf-8",
        limits=limits,
    )


def _ingest_pdf(
    data: bytes | bytearray | memoryview,
    filename: str | Path | None = None,
    media_type: str = "application/pdf",
    *,
    limits: DocumentLimits,
    reader_factory: Any | None = None,
) -> IngestedDocument:
    payload = _as_bytes(data, limits)
    normalized_media_type = _normalize_media_type(media_type)
    if normalized_media_type not in _PDF_MEDIA_TYPES:
        raise UnsupportedDocumentError(
            f"Unsupported PDF media type: {normalized_media_type!r}."
        )
    header_offset = _pdf_header_offset(payload)
    if header_offset is None:
        raise UnsupportedDocumentError(
            "PDF data does not contain a valid PDF header."
        )
    return _extract_pdf(
        payload[header_offset:],
        source_name=_safe_source_name(filename, default="document.pdf"),
        media_type="application/pdf",
        limits=limits,
        reader_factory=reader_factory,
    )


def _ingest_path(
    path: str | Path,
    media_type: str | None = None,
    *,
    limits: DocumentLimits,
    reader_factory: Any | None = None,
) -> IngestedDocument:
    source_path = Path(path)
    try:
        file_size = source_path.stat().st_size
    except OSError as exc:
        raise DocumentExtractionError(
            f"Document could not be inspected: {source_path.name}."
        ) from exc

    if file_size > limits.max_document_bytes:
        raise DocumentTooLargeError(
            "Document exceeds the maximum byte size.",
            limit=limits.max_document_bytes,
            actual=file_size,
        )

    try:
        with source_path.open("rb") as stream:
            payload = stream.read(limits.max_document_bytes + 1)
    except OSError as exc:
        raise DocumentExtractionError(
            f"Document could not be read: {source_path.name}."
        ) from exc

    inferred_media_type = media_type
    if inferred_media_type is None:
        inferred_media_type = _TEXT_SUFFIXES.get(source_path.suffix.lower())

    return _ingest_bytes(
        payload,
        filename=source_path.name,
        media_type=inferred_media_type,
        limits=limits,
        reader_factory=reader_factory,
    )


def _extract_document(
    source: str | bytes | bytearray | memoryview | Path | BinaryIO,
    *,
    filename: str | Path | None = None,
    media_type: str | None = None,
    limits: DocumentLimits,
    reader_factory: Any | None = None,
) -> IngestedDocument:
    if isinstance(source, IngestedDocument):
        return source
    if isinstance(source, (bytes, bytearray, memoryview)):
        return _ingest_bytes(
            source,
            filename=filename,
            media_type=media_type,
            limits=limits,
            reader_factory=reader_factory,
        )
    if isinstance(source, Path):
        return _ingest_path(
            source,
            media_type=media_type,
            limits=limits,
            reader_factory=reader_factory,
        )
    if isinstance(source, str):
        candidate = Path(source)
        try:
            is_file = candidate.is_file()
        except OSError:
            is_file = False
        if is_file or (
            "\n" not in source
            and "\r" not in source
            and len(source) <= 4_096
            and candidate.suffix.lower() in {".pdf", *_TEXT_SUFFIXES}
        ):
            return _ingest_path(
                candidate,
                media_type=media_type,
                limits=limits,
                reader_factory=reader_factory,
            )
        return _ingest_text(
            source,
            source_name=filename,
            media_type=media_type or "text/plain",
            limits=limits,
        )
    if hasattr(source, "read"):
        payload = source.read(limits.max_document_bytes + 1)
        if payload is None:
            raise DocumentExtractionError("Document stream returned no data.")
        if isinstance(payload, str):
            payload = payload.encode("utf-8")
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise DocumentExtractionError(
                "Document stream returned unsupported data."
            )
        return _ingest_bytes(
            payload,
            filename=filename,
            media_type=media_type,
            limits=limits,
            reader_factory=reader_factory,
        )

    raise TypeError("Unsupported document source.")


def ingest_bytes(
    data: bytes | bytearray | memoryview,
    filename: str | Path | None = None,
    media_type: str | None = None,
    *,
    limits: DocumentLimits | Mapping[str, int] | None = None,
    max_document_bytes: int | None = None,
    max_document_characters: int | None = None,
    max_pdf_pages: int | None = None,
    reader_factory: Any | None = None,
) -> IngestedDocument:
    """Extract a complete PDF or plain-text upload without chunking."""

    ingestor = _make_ingestor(
        limits,
        max_document_bytes,
        max_document_characters,
        max_pdf_pages,
    )
    ingestor._reader_factory = reader_factory
    return ingestor.ingest_bytes(data, filename, media_type)


def ingest_text(
    text: str,
    source_name: str | Path | None = None,
    media_type: str = "text/plain",
    *,
    limits: DocumentLimits | Mapping[str, int] | None = None,
    max_document_bytes: int | None = None,
    max_document_characters: int | None = None,
    max_pdf_pages: int | None = None,
) -> IngestedDocument:
    """Normalize and ingest one complete plain-text document."""

    ingestor = _make_ingestor(
        limits,
        max_document_bytes,
        max_document_characters,
        max_pdf_pages,
    )
    return ingestor.ingest_text(text, source_name, media_type)


def ingest_pdf(
    data: bytes | bytearray | memoryview,
    filename: str | Path | None = None,
    media_type: str = "application/pdf",
    *,
    limits: DocumentLimits | Mapping[str, int] | None = None,
    max_document_bytes: int | None = None,
    max_document_characters: int | None = None,
    max_pdf_pages: int | None = None,
    reader_factory: Any | None = None,
) -> IngestedDocument:
    """Extract every page from one complete PDF in page order."""

    ingestor = _make_ingestor(
        limits,
        max_document_bytes,
        max_document_characters,
        max_pdf_pages,
    )
    ingestor._reader_factory = reader_factory
    return ingestor.ingest_pdf(data, filename, media_type)


def ingest_path(
    path: str | Path,
    media_type: str | None = None,
    *,
    limits: DocumentLimits | Mapping[str, int] | None = None,
    max_document_bytes: int | None = None,
    max_document_characters: int | None = None,
    max_pdf_pages: int | None = None,
    reader_factory: Any | None = None,
) -> IngestedDocument:
    """Read and completely extract a local PDF or text document."""

    ingestor = _make_ingestor(
        limits,
        max_document_bytes,
        max_document_characters,
        max_pdf_pages,
    )
    ingestor._reader_factory = reader_factory
    return ingestor.ingest_path(path, media_type)


def extract_document(
    source: str | bytes | bytearray | memoryview | Path | BinaryIO,
    *,
    filename: str | Path | None = None,
    media_type: str | None = None,
    limits: DocumentLimits | Mapping[str, int] | None = None,
    max_document_bytes: int | None = None,
    max_document_characters: int | None = None,
    max_pdf_pages: int | None = None,
    reader_factory: Any | None = None,
) -> IngestedDocument:
    """Extract a document from bytes, text, a path, or a binary stream."""

    ingestor = _make_ingestor(
        limits,
        max_document_bytes,
        max_document_characters,
        max_pdf_pages,
    )
    ingestor._reader_factory = reader_factory
    return ingestor.extract_document(
        source,
        filename=filename,
        media_type=media_type,
    )


def extract_text(
    source: str | bytes | bytearray | memoryview | Path | BinaryIO,
    *,
    filename: str | Path | None = None,
    media_type: str | None = None,
    limits: DocumentLimits | Mapping[str, int] | None = None,
    max_document_bytes: int | None = None,
    max_document_characters: int | None = None,
    max_pdf_pages: int | None = None,
    reader_factory: Any | None = None,
) -> str:
    """Return only the complete normalized extracted document text."""

    return extract_document(
        source,
        filename=filename,
        media_type=media_type,
        limits=limits,
        max_document_bytes=max_document_bytes,
        max_document_characters=max_document_characters,
        max_pdf_pages=max_pdf_pages,
        reader_factory=reader_factory,
    ).text


__all__ = [
    "DEFAULT_MAX_DOCUMENT_BYTES",
    "DEFAULT_MAX_DOCUMENT_CHARACTERS",
    "DEFAULT_MAX_PDF_PAGES",
    "Document",
    "DocumentError",
    "DocumentExtractionError",
    "DocumentIngestor",
    "DocumentLimits",
    "DocumentTooLargeError",
    "EmptyDocumentError",
    "ExtractedDocument",
    "IngestedDocument",
    "PageSpan",
    "UnsupportedDocumentError",
    "extract_document",
    "extract_text",
    "ingest_bytes",
    "ingest_path",
    "ingest_pdf",
    "ingest_text",
]