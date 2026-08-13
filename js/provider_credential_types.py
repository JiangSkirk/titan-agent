"""Dependency-light, non-secret Provider credential reference types."""

from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

ProductId = Literal["js-agent", "js-work"]
CredentialKind = Literal["model_provider", "search_provider"]
_REF_ID_PATTERN = re.compile(r"[0-9a-f]{32}\Z")


class ProviderCredentialRefV1(BaseModel):
    """Strict, immutable and non-secret reference persisted in configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True, strict=True)

    ref_id: str = Field(min_length=32, max_length=32)
    product_id: ProductId
    kind: CredentialKind

    @field_validator("ref_id")
    @classmethod
    def _valid_ref_id(cls, value: str) -> str:
        if _REF_ID_PATTERN.fullmatch(value) is None:
            raise ValueError("credential reference is malformed")
        return value

    def __repr__(self) -> str:
        return (
            "ProviderCredentialRefV1(ref_id='<redacted>', "
            f"product_id='{self.product_id}', kind='{self.kind}')"
        )

    __str__ = __repr__
