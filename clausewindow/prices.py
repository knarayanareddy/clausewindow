"""Deterministic token and review-cost accounting.

Token counts produced without a provider tokenizer are estimates, not billable
usage. Production callers should pass provider-reported counts through
:class:`TokenUsage` when those counts are available.

All monetary calculations use :class:`~decimal.Decimal`; binary floating-point
arithmetic is never used for invoice-facing calculations. The built-in price
catalog is a dated estimate and should be refreshed or replaced with a
contract-specific :class:`ModelPrice` when provider pricing changes.
"""

from __future__ import annotations

import operator
import unicodedata
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from decimal import Decimal, InvalidOperation
from types import MappingProxyType
from typing import Final


MILLION_TOKENS: Final[Decimal] = Decimal("1000000")
DEFAULT_REVIEW_MODEL: Final[str] = "google/gemini-2.5-flash"
DETERMINISTIC_MODEL: Final[str] = "deterministic-heuristic"

TokenCounter = Callable[[str], int]


class PriceError(ValueError):
    """Base exception for invalid pricing inputs."""


class UnknownModelError(PriceError):
    """Raised when a model has no configured token price."""


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string.")
    return value


def _require_identifier(value: object, field_name: str) -> str:
    text = _require_text(value, field_name).strip()
    if not text:
        raise ValueError(f"{field_name} must not be blank.")
    if len(text) > 300:
        raise ValueError(f"{field_name} must not exceed 300 characters.")
    return text


def _require_token_count(value: object, field_name: str) -> int:
    if isinstance(value, bool):
        raise TypeError(f"{field_name} must be an integer, not a boolean.")
    try:
        normalized = operator.index(value)
    except TypeError as exc:
        raise TypeError(f"{field_name} must be an integer.") from exc
    if normalized < 0:
        raise ValueError(f"{field_name} must not be negative.")
    return int(normalized)


def _to_usd_decimal(value: object, field_name: str) -> Decimal:
    if isinstance(value, bool):
        raise TypeError(f"{field_name} must be numeric, not a boolean.")
    try:
        normalized = (
            value
            if isinstance(value, Decimal)
            else Decimal(str(value))
        )
    except (InvalidOperation, TypeError, ValueError) as exc:
        raise ValueError(f"{field_name} must be a valid decimal.") from exc
    if not normalized.is_finite():
        raise ValueError(f"{field_name} must be finite.")
    if normalized < 0:
        raise ValueError(f"{field_name} must not be negative.")
    return normalized


def _is_cjk(character: str) -> bool:
    codepoint = ord(character)
    return (
        0x3400 <= codepoint <= 0x4DBF
        or 0x4E00 <= codepoint <= 0x9FFF
        or 0xF900 <= codepoint <= 0xFAFF
        or 0x20000 <= codepoint <= 0x3134F
        or 0x3040 <= codepoint <= 0x30FF
        or 0xAC00 <= codepoint <= 0xD7AF
    )


def _approximate_lexical_tokens(text: str) -> int:
    """Estimate tokens from words, punctuation, and CJK characters."""

    total = 0
    word: list[str] = []

    def flush_word() -> None:
        nonlocal total
        if not word:
            return
        value = "".join(word)
        substantive = "".join(
            character
            for character in value
            if unicodedata.category(character)[0] in {"L", "N"}
        )
        if substantive and all(_is_cjk(character) for character in substantive):
            total += len(substantive)
        else:
            total += max(1, (len(value) + 3) // 4)
        word.clear()

    for character in text:
        if (
            character == "_"
            or character.isalnum()
            or unicodedata.combining(character)
        ):
            word.append(character)
            continue
        flush_word()
        if not character.isspace():
            total += 1
    flush_word()
    return total


def estimate_token_count(text: str) -> int:
    """Return a conservative, tokenizer-independent token estimate.

    The estimate combines a lexical approximation with a UTF-8 byte heuristic.
    It is suitable for budgeting but must not be represented as provider-exact
    usage. Empty or whitespace-only input consumes zero estimated tokens.
    """

    text = _require_text(text, "text")
    if not text.strip():
        return 0
    try:
        encoded = text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("text must contain valid Unicode scalar values.") from exc
    byte_estimate = (len(encoded) + 3) // 4
    return max(_approximate_lexical_tokens(text), byte_estimate)


count_tokens = estimate_token_count
estimate_tokens = estimate_token_count


def _count_text(text: str, token_counter: TokenCounter | None) -> int:
    if not text.strip():
        return 0
    if token_counter is None:
        return estimate_token_count(text)
    return _require_token_count(
        token_counter(text),
        "token_counter return value",
    )


@dataclass(frozen=True, slots=True)
class TokenUsage:
    """Input and output token counts for one model request."""

    input_tokens: int
    output_tokens: int = 0

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "input_tokens",
            _require_token_count(self.input_tokens, "input_tokens"),
        )
        object.__setattr__(
            self,
            "output_tokens",
            _require_token_count(self.output_tokens, "output_tokens"),
        )

    @property
    def total_tokens(self) -> int:
        """Return total input plus output tokens."""

        return self.input_tokens + self.output_tokens

    def as_dict(self) -> dict[str, int]:
        """Return a JSON-compatible token usage object."""

        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
        }


def estimate_token_usage(
    input_text: str,
    output_text: str = "",
    *,
    token_counter: TokenCounter | None = None,
) -> TokenUsage:
    """Measure request token usage using an exact optional provider counter.

    When ``token_counter`` is absent, :func:`estimate_token_count` is used.
    """

    input_text = _require_text(input_text, "input_text")
    output_text = _require_text(output_text, "output_text")
    return TokenUsage(
        input_tokens=_count_text(input_text, token_counter),
        output_tokens=_count_text(output_text, token_counter),
    )


def estimate_review_usage(
    document: str,
    playbook: str = "",
    *,
    instructions: str = "",
    response: str = "",
    token_counter: TokenCounter | None = None,
) -> TokenUsage:
    """Estimate a complete review request without splitting the document.

    Instructions, the full contract, and the full playbook are assembled in a
    stable order with a double-newline separator. The document is counted as
    one complete input, preserving its original unbroken content.
    """

    document = _require_text(document, "document")
    playbook = _require_text(playbook, "playbook")
    instructions = _require_text(instructions, "instructions")
    response = _require_text(response, "response")

    input_parts = tuple(
        part for part in (instructions, document, playbook) if part.strip()
    )
    input_text = "\n\n".join(input_parts)
    return estimate_token_usage(
        input_text,
        response,
        token_counter=token_counter,
    )


@dataclass(frozen=True, slots=True)
class ModelPrice:
    """USD token rates for one model, expressed per million tokens."""

    model_id: str
    input_usd_per_million_tokens: Decimal | int | float | str
    output_usd_per_million_tokens: Decimal | int | float | str
    provider: str = "unknown"
    currency: str = "USD"
    source: str = "configured estimate"

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "model_id",
            _require_identifier(self.model_id, "model_id"),
        )
        object.__setattr__(
            self,
            "provider",
            _require_identifier(self.provider, "provider"),
        )
        object.__setattr__(
            self,
            "source",
            _require_identifier(self.source, "source"),
        )
        object.__setattr__(
            self,
            "input_usd_per_million_tokens",
            _to_usd_decimal(
                self.input_usd_per_million_tokens,
                "input_usd_per_million_tokens",
            ),
        )
        object.__setattr__(
            self,
            "output_usd_per_million_tokens",
            _to_usd_decimal(
                self.output_usd_per_million_tokens,
                "output_usd_per_million_tokens",
            ),
        )
        currency = _require_identifier(self.currency, "currency").upper()
        if currency != "USD":
            raise ValueError("Only USD model prices are supported.")
        object.__setattr__(self, "currency", currency)

    @property
    def input_per_million(self) -> Decimal:
        """Return the configured input rate per million tokens."""

        return self.input_usd_per_million_tokens

    @property
    def output_per_million(self) -> Decimal:
        """Return the configured output rate per million tokens."""

        return self.output_usd_per_million_tokens

    @property
    def input_price_per_1k_tokens(self) -> Decimal:
        """Return the configured input rate per thousand tokens."""

        return self.input_usd_per_million_tokens / Decimal("1000")

    @property
    def output_price_per_1k_tokens(self) -> Decimal:
        """Return the configured output rate per thousand tokens."""

        return self.output_usd_per_million_tokens / Decimal("1000")

    def calculate_cost(
        self,
        input_tokens: int,
        output_tokens: int = 0,
    ) -> Decimal:
        """Calculate unrounded USD cost for the supplied token usage."""

        usage = TokenUsage(input_tokens, output_tokens)
        input_cost = (
            Decimal(usage.input_tokens) * self.input_usd_per_million_tokens
        ) / MILLION_TOKENS
        output_cost = (
            Decimal(usage.output_tokens) * self.output_usd_per_million_tokens
        ) / MILLION_TOKENS
        return input_cost + output_cost


ModelPricing = ModelPrice


# These rates are estimates captured for budgeting. They are not a live price
# feed and must be refreshed before they are used for an invoice.
BUILTIN_MODEL_PRICES: Final[
    Mapping[str, ModelPrice]
] = MappingProxyType(
    {
        DETERMINISTIC_MODEL: ModelPrice(
            model_id=DETERMINISTIC_MODEL,
            input_usd_per_million_tokens=Decimal("0"),
            output_usd_per_million_tokens=Decimal("0"),
            provider="clausewindow",
            source="deterministic local processing",
        ),
        "stealth/space-bunny-alpha": ModelPrice(
            model_id="stealth/space-bunny-alpha",
            input_usd_per_million_tokens=Decimal("0.50"),
            output_usd_per_million_tokens=Decimal("1.50"),
            provider="openrouter",
            source="ClauseWindow catalog estimate",
        ),
        "qwen/qwen-2.5-72b-instruct": ModelPrice(
            model_id="qwen/qwen-2.5-72b-instruct",
            input_usd_per_million_tokens=Decimal("0.12"),
            output_usd_per_million_tokens=Decimal("0.39"),
            provider="openrouter",
            source="ClauseWindow catalog estimate",
        ),
        "google/gemini-2.5-flash": ModelPrice(
            model_id="google/gemini-2.5-flash",
            input_usd_per_million_tokens=Decimal("0.30"),
            output_usd_per_million_tokens=Decimal("2.50"),
            provider="google",
            source="ClauseWindow catalog estimate",
        ),
    }
)

MODEL_PRICES = BUILTIN_MODEL_PRICES
PRICING = BUILTIN_MODEL_PRICES

_MODEL_ALIASES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "heuristic": DETERMINISTIC_MODEL,
        "local-heuristic": DETERMINISTIC_MODEL,
        "space-bunny-alpha": "stealth/space-bunny-alpha",
        "qwen": "qwen/qwen-2.5-72b-instruct",
        "qwen-2.5-72b-instruct": "qwen/qwen-2.5-72b-instruct",
        "gemini-2.5-flash": "google/gemini-2.5-flash",
        "gemini-2.5-flash-preview": "google/gemini-2.5-flash",
    }
)


def normalize_model_id(model: str) -> str:
    """Normalize a configured model identifier for catalog lookup."""

    normalized = _require_identifier(model, "model").casefold()
    if normalized.startswith("openrouter/"):
        normalized = normalized.removeprefix("openrouter/")
    normalized = "-".join(normalized.split())
    return _MODEL_ALIASES.get(normalized, normalized)


def get_model_price(model: str = DEFAULT_REVIEW_MODEL) -> ModelPrice:
    """Return an immutable built-in price for a supported model."""

    canonical = normalize_model_id(model)
    try:
        return BUILTIN_MODEL_PRICES[canonical]
    except KeyError as exc:
        supported = ", ".join(sorted(BUILTIN_MODEL_PRICES))
        raise UnknownModelError(
            f"No token price is configured for {model!r}. "
            f"Supported models: {supported}. Supply an explicit ModelPrice."
        ) from exc


def resolve_model_price(
    model: str | None = DEFAULT_REVIEW_MODEL,
    price: ModelPrice | None = None,
) -> ModelPrice:
    """Resolve a custom price or retrieve a built-in model price."""

    if price is not None:
        if not isinstance(price, ModelPrice):
            raise TypeError("price must be a ModelPrice instance.")
        return price
    return get_model_price(model or DEFAULT_REVIEW_MODEL)


@dataclass(frozen=True, slots=True)
class CostEstimate:
    """Detailed, unrounded USD cost estimate for one review request."""

    model_id: str
    usage: TokenUsage
    price: ModelPrice
    input_cost_usd: Decimal | int | float | str
    output_cost_usd: Decimal | int | float | str
    total_cost_usd: Decimal | int | float | str
    currency: str = "USD"

    def __post_init__(self) -> None:
        if not isinstance(self.usage, TokenUsage):
            raise TypeError("usage must be a TokenUsage instance.")
        if not isinstance(self.price, ModelPrice):
            raise TypeError("price must be a ModelPrice instance.")

        model_id = _require_identifier(self.model_id, "model_id")
        if model_id != self.price.model_id:
            raise ValueError("model_id must match the selected ModelPrice.")
        currency = _require_identifier(self.currency, "currency").upper()
        if currency != "USD" or self.price.currency != "USD":
            raise ValueError("Only USD cost estimates are supported.")

        input_cost = _to_usd_decimal(
            self.input_cost_usd,
            "input_cost_usd",
        )
        output_cost = _to_usd_decimal(
            self.output_cost_usd,
            "output_cost_usd",
        )
        total_cost = _to_usd_decimal(
            self.total_cost_usd,
            "total_cost_usd",
        )
        if total_cost != input_cost + output_cost:
            raise ValueError(
                "total_cost_usd must equal input_cost_usd plus output_cost_usd."
            )

        object.__setattr__(self, "model_id", model_id)
        object.__setattr__(self, "currency", currency)
        object.__setattr__(self, "input_cost_usd", input_cost)
        object.__setattr__(self, "output_cost_usd", output_cost)
        object.__setattr__(self, "total_cost_usd", total_cost)

    @property
    def model(self) -> str:
        """Return the priced model identifier."""

        return self.model_id

    @property
    def estimated_cost_usd(self) -> Decimal:
        """Return the total estimated USD cost."""

        return self.total_cost_usd

    def rounded_total_usd(self, places: int = 6) -> Decimal:
        """Return total cost rounded to a caller-selected decimal place."""

        places = _require_token_count(places, "places")
        if places > 18:
            raise ValueError("places must not exceed 18.")
        quantum = Decimal(1).scaleb(-places)
        return self.total_cost_usd.quantize(quantum)

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-compatible representation with exact decimal text."""

        return {
            "model_id": self.model_id,
            "provider": self.price.provider,
            "currency": self.currency,
            "usage": self.usage.as_dict(),
            "input_cost_usd": format(self.input_cost_usd, "f"),
            "output_cost_usd": format(self.output_cost_usd, "f"),
            "total_cost_usd": format(self.total_cost_usd, "f"),
            "price_source": self.price.source,
        }


def build_cost_estimate(
    usage: TokenUsage,
    *,
    model: str = DEFAULT_REVIEW_MODEL,
    price: ModelPrice | None = None,
) -> CostEstimate:
    """Build a detailed cost estimate from validated token usage."""

    if not isinstance(usage, TokenUsage):
        raise TypeError("usage must be a TokenUsage instance.")
    resolved_price = resolve_model_price(model, price)
    input_cost = (
        Decimal(usage.input_tokens)
        * resolved_price.input_usd_per_million_tokens
    ) / MILLION_TOKENS
    output_cost = (
        Decimal(usage.output_tokens)
        * resolved_price.output_usd_per_million_tokens
    ) / MILLION_TOKENS
    return CostEstimate(
        model_id=resolved_price.model_id,
        usage=usage,
        price=resolved_price,
        input_cost_usd=input_cost,
        output_cost_usd=output_cost,
        total_cost_usd=input_cost + output_cost,
    )


def calculate_cost(
    input_tokens: int,
    output_tokens: int = 0,
    *,
    model: str = DEFAULT_REVIEW_MODEL,
    price: ModelPrice | None = None,
) -> Decimal:
    """Calculate the estimated USD cost for token counts."""

    return build_cost_estimate(
        TokenUsage(input_tokens, output_tokens),
        model=model,
        price=price,
    ).total_cost_usd


estimate_cost = calculate_cost


def estimate_review_cost(
    document: str,
    playbook: str = "",
    *,
    instructions: str = "",
    response: str = "",
    model: str = DEFAULT_REVIEW_MODEL,
    price: ModelPrice | None = None,
    token_counter: TokenCounter | None = None,
) -> CostEstimate:
    """Estimate complete review token usage and USD model cost."""

    usage = estimate_review_usage(
        document,
        playbook,
        instructions=instructions,
        response=response,
        token_counter=token_counter,
    )
    return build_cost_estimate(usage, model=model, price=price)


def calculate_review_cost(
    document: str,
    playbook: str = "",
    *,
    instructions: str = "",
    response: str = "",
    model: str = DEFAULT_REVIEW_MODEL,
    price: ModelPrice | None = None,
    token_counter: TokenCounter | None = None,
) -> Decimal:
    """Return only the total estimated USD review cost."""

    return estimate_review_cost(
        document,
        playbook,
        instructions=instructions,
        response=response,
        model=model,
        price=price,
        token_counter=token_counter,
    ).total_cost_usd


__all__ = [
    "BUILTIN_MODEL_PRICES",
    "DEFAULT_REVIEW_MODEL",
    "DETERMINISTIC_MODEL",
    "MILLION_TOKENS",
    "MODEL_PRICES",
    "PRICING",
    "CostEstimate",
    "ModelPrice",
    "ModelPricing",
    "PriceError",
    "TokenCounter",
    "TokenUsage",
    "UnknownModelError",
    "build_cost_estimate",
    "calculate_cost",
    "calculate_review_cost",
    "count_tokens",
    "estimate_cost",
    "estimate_review_cost",
    "estimate_review_usage",
    "estimate_token_count",
    "estimate_token_usage",
    "estimate_tokens",
    "get_model_price",
    "normalize_model_id",
    "resolve_model_price",
]