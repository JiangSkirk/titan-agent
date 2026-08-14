"""Unforgeable, single-use model-call permits for the Echo runtime boundary.

Every real provider call made through :class:`js.models.router.ModelRouter`
must carry a fresh :class:`ModelPermit` issued by a :class:`ModelPermitIssuer`
owned by the Echo turn runtime.  The permit is bound to the concrete routing
decision (provider + model), the exact messages hash, the tools schema hash,
and the product/owner/session/run identity, and it can be consumed exactly
once.  There is intentionally **no** public way to (re)install authorization
callbacks on the router: identity comes from this cryptographic capability,
not from a Python function object that any caller could replace.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import threading
import time
from dataclasses import dataclass, replace
from typing import Any

from js.models.providers import ChatMessage


class ModelPermitError(PermissionError):
    """Raised when a model-call permit is missing, forged, stale, or spent."""


def _canonical_json(payload: Any) -> str:
    return json.dumps(payload, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def _bound_str_eq(left: str, right: str) -> bool:
    a = (left or "").encode("utf-8")
    b = (right or "").encode("utf-8")
    if len(a) != len(b):
        hmac.compare_digest(hashlib.sha256(a).digest(), hashlib.sha256(b).digest())
        return False
    return hmac.compare_digest(a, b)


def hash_messages(messages: list[ChatMessage]) -> str:
    """Deterministic SHA-256 over the exact messages that will be sent."""
    canonical = [
        {
            "role": message.role,
            "content": message.content,
            "tool_calls": message.tool_calls,
            "tool_call_id": message.tool_call_id,
            "name": message.name,
            "reasoning_content": message.reasoning_content,
        }
        for message in messages
    ]
    return hashlib.sha256(_canonical_json(canonical).encode("utf-8")).hexdigest()


def hash_tools_schema(tools: list[dict[str, Any]] | None) -> str:
    """Deterministic SHA-256 over the exact tools schema (empty when absent)."""
    return hashlib.sha256(_canonical_json(tools or []).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class ModelPermit:
    """A single-use, HMAC-signed authorization for one provider attempt."""

    provider_name: str
    model: str
    messages_digest: str
    tools_digest: str
    owner_key_hash: str
    session_id: str
    run_id: str
    nonce: str
    expires_at: float
    mac: str
    attempt_hash: str = ""
    attempt_id: str = ""
    consent_receipt_hash: str = ""
    channel: str = ""
    provider_generation: str = ""
    endpoint_digest: str = ""
    attachments_digest: str = ""
    provenance_digest: str = ""
    temperature: float = 0.0
    effective_max_tokens: int | None = None
    appshell_epoch: str | None = None

    def _payload(self) -> str:
        return _canonical_json(
            {
                "provider_name": self.provider_name,
                "model": self.model,
                "messages_digest": self.messages_digest,
                "tools_digest": self.tools_digest,
                "owner_key_hash": self.owner_key_hash,
                "session_id": self.session_id,
                "run_id": self.run_id,
                "nonce": self.nonce,
                "expires_at": self.expires_at,
                "attempt_hash": self.attempt_hash,
                "attempt_id": self.attempt_id,
                "consent_receipt_hash": self.consent_receipt_hash,
                "channel": self.channel,
                "provider_generation": self.provider_generation,
                "endpoint_digest": self.endpoint_digest,
                "attachments_digest": self.attachments_digest,
                "provenance_digest": self.provenance_digest,
                "temperature": self.temperature,
                "effective_max_tokens": self.effective_max_tokens,
                "appshell_epoch": self.appshell_epoch,
            }
        )


class ModelPermitIssuer:
    """Issues and verifies model-call permits.

    The instance holds a per-runtime random HMAC key.  The Echo turn runtime
    owns the issuer; the router only receives it as a *verifier* at
    construction time.  Permits are single-use: ``verify_and_consume``
    permanently spends the nonce, so retries, fallbacks and stream reconnects
    each require a freshly issued permit.
    """

    # Soft default for long-running daemons: enough for concurrent turns while
    # still bounding memory.  Unexpired nonces are never evicted to make room.
    _DEFAULT_MAX_SPENT_NONCES = 10_000

    def __init__(
        self,
        *,
        key: bytes | None = None,
        ttl_seconds: float = 60.0,
        max_spent_nonces: int | None = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("permit ttl_seconds must be positive")
        limit = (
            self._DEFAULT_MAX_SPENT_NONCES if max_spent_nonces is None else int(max_spent_nonces)
        )
        if limit < 1:
            raise ValueError("max_spent_nonces must be positive")
        self._key = key if key is not None else os.urandom(32)
        if len(self._key) < 32:
            raise ValueError("permit key must be at least 32 bytes")
        self._ttl_seconds = float(ttl_seconds)
        self._max_spent_nonces = limit
        # nonce -> expires_at of the permit that spent it
        self._spent_nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    def spent_nonce_count(self) -> int:
        """Number of currently retained spent nonces (for tests / metrics)."""
        with self._lock:
            return len(self._spent_nonces)

    def _purge_expired_unlocked(self, *, now: float) -> None:
        expired = [nonce for nonce, expires_at in self._spent_nonces.items() if expires_at <= now]
        for nonce in expired:
            del self._spent_nonces[nonce]

    def issue(
        self,
        *,
        provider_name: str,
        model: str,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        attempt_hash: str = "",
        attempt_id: str = "",
        consent_receipt_hash: str = "",
        channel: str = "",
        provider_generation: str = "",
        endpoint_digest: str = "",
        attachments_digest: str = "",
        provenance_digest: str = "",
        temperature: float = 0.0,
        effective_max_tokens: int | None = None,
        appshell_epoch: str | None = None,
    ) -> ModelPermit:
        permit = ModelPermit(
            provider_name=provider_name,
            model=model,
            messages_digest=hash_messages(messages),
            tools_digest=hash_tools_schema(tools),
            owner_key_hash=owner_key_hash,
            session_id=session_id,
            run_id=run_id,
            nonce=secrets.token_hex(16),
            expires_at=time.time() + self._ttl_seconds,
            mac="",
            attempt_hash=attempt_hash,
            attempt_id=attempt_id,
            consent_receipt_hash=consent_receipt_hash,
            channel=channel,
            provider_generation=provider_generation,
            endpoint_digest=endpoint_digest,
            attachments_digest=attachments_digest,
            provenance_digest=provenance_digest,
            temperature=temperature,
            effective_max_tokens=effective_max_tokens,
            appshell_epoch=appshell_epoch,
        )
        return replace(permit, mac=self._mac(permit))

    def _mac(self, permit: ModelPermit) -> str:
        return hmac.new(self._key, permit._payload().encode("utf-8"), hashlib.sha256).hexdigest()

    def verify_and_consume(
        self,
        permit: ModelPermit | Any,
        *,
        provider_name: str,
        model: str,
        messages: list[ChatMessage],
        tools: list[dict[str, Any]] | None,
        owner_key_hash: str | None = None,
        session_id: str | None = None,
        run_id: str | None = None,
        attempt_hash: str | None = None,
        attempt_id: str | None = None,
        consent_receipt_hash: str | None = None,
        channel: str | None = None,
        provider_generation: str | None = None,
        endpoint_digest: str | None = None,
        attachments_digest: str | None = None,
        provenance_digest: str | None = None,
        temperature: float | None = None,
        effective_max_tokens: int | None = None,
        appshell_epoch: str | None = None,
    ) -> None:
        """Verify a permit and permanently spend its nonce (fail-closed)."""
        if not isinstance(permit, ModelPermit):
            raise ModelPermitError("model permit missing or not a ModelPermit")
        expected_mac = self._mac(permit)
        if not hmac.compare_digest(expected_mac, permit.mac):
            raise ModelPermitError("model permit MAC mismatch (forged or wrong issuer)")
        # Reject expiry before taking the anti-replay lock...
        if time.time() >= permit.expires_at:
            raise ModelPermitError("model permit expired")
        if permit.provider_name != provider_name or permit.model != model:
            raise ModelPermitError("model permit does not match the routing decision")
        if not hmac.compare_digest(permit.messages_digest, hash_messages(messages)):
            raise ModelPermitError("model permit does not match the request messages")
        if not hmac.compare_digest(permit.tools_digest, hash_tools_schema(tools)):
            raise ModelPermitError("model permit does not match the request tools schema")
        bound = bool(permit.attempt_hash) or attempt_hash is not None
        if bound:
            if owner_key_hash is None or not hmac.compare_digest(
                permit.owner_key_hash, owner_key_hash
            ):
                raise ModelPermitError("model permit does not match the trusted owner")
            if session_id is None or not hmac.compare_digest(permit.session_id, session_id):
                raise ModelPermitError("model permit does not match the session")
            if run_id is None or not hmac.compare_digest(permit.run_id, run_id):
                raise ModelPermitError("model permit does not match the run")
            if attempt_hash is None or not hmac.compare_digest(permit.attempt_hash, attempt_hash):
                raise ModelPermitError("model permit does not match the egress attempt")
            if (permit.attempt_id or attempt_id) and (
                attempt_id is None or not hmac.compare_digest(permit.attempt_id, attempt_id)
            ):
                raise ModelPermitError("model permit does not match the attempt identity")
            if consent_receipt_hash is None or not hmac.compare_digest(
                permit.consent_receipt_hash, consent_receipt_hash
            ):
                raise ModelPermitError("model permit does not match the consent receipt")
            if channel is None or permit.channel != channel:
                raise ModelPermitError("model permit does not match the channel")
            if provider_generation is None or permit.provider_generation != provider_generation:
                raise ModelPermitError("model permit does not match the provider generation")
            if endpoint_digest is None or not hmac.compare_digest(
                permit.endpoint_digest, endpoint_digest
            ):
                raise ModelPermitError("model permit does not match the endpoint")
            if attachments_digest is None or not hmac.compare_digest(
                permit.attachments_digest, attachments_digest
            ):
                raise ModelPermitError("model permit does not match the attachments")
            if provenance_digest is None or not hmac.compare_digest(
                permit.provenance_digest, provenance_digest
            ):
                raise ModelPermitError("model permit does not match the provenance")
            if temperature is None or permit.temperature != temperature:
                raise ModelPermitError("model permit does not match the temperature")
            if permit.effective_max_tokens != effective_max_tokens:
                raise ModelPermitError("model permit does not match effective max_tokens")
            if (permit.appshell_epoch or "") != (appshell_epoch or ""):
                raise ModelPermitError("model permit does not match the AppShell epoch")
        with self._lock:
            now = time.time()
            # Recheck expiry under the lock so a permit that expired while
            # waiting cannot still be accepted.
            if now >= permit.expires_at:
                raise ModelPermitError("model permit expired")
            self._purge_expired_unlocked(now=now)
            existing_expiry = self._spent_nonces.get(permit.nonce)
            if existing_expiry is not None and existing_expiry > now:
                raise ModelPermitError("model permit replayed (nonce already consumed)")
            if len(self._spent_nonces) >= self._max_spent_nonces:
                # Never evict an unexpired nonce to free capacity — fail closed
                # so the provider call cannot proceed without anti-replay state.
                raise ModelPermitError(
                    "model permit spent nonce capacity exhausted; refuse provider call"
                )
            self._spent_nonces[permit.nonce] = permit.expires_at


class NetworkEgressPermitError(PermissionError):
    """Raised when a non-model network permit is missing, forged, stale, or spent."""


_NETWORK_PERMIT_MAC_DOMAIN = "js.network_egress.permit.v1"


@dataclass(frozen=True)
class NetworkEgressPermit:
    """Single-use HMAC authorization for one non-model network attempt."""

    kind: str
    attempt_id: str
    attempt_hash: str
    owner_key_hash: str
    session_id: str
    run_id: str
    channel: str
    product_id: str
    endpoint_generation: str
    credential_generation: str
    payload_digest: str
    provenance_digest: str
    consent_receipt_hash: str
    nonce: str
    expires_at: float
    mac: str
    appshell_epoch: str | None = None
    effect_id: str = ""
    arguments_hash: str = ""
    endpoint_digest: str = ""

    def _payload(self) -> str:
        return _canonical_json(
            {
                "mac_domain": _NETWORK_PERMIT_MAC_DOMAIN,
                "kind": self.kind,
                "attempt_id": self.attempt_id,
                "attempt_hash": self.attempt_hash,
                "owner_key_hash": self.owner_key_hash,
                "session_id": self.session_id,
                "run_id": self.run_id,
                "channel": self.channel,
                "product_id": self.product_id,
                "endpoint_generation": self.endpoint_generation,
                "credential_generation": self.credential_generation,
                "payload_digest": self.payload_digest,
                "provenance_digest": self.provenance_digest,
                "consent_receipt_hash": self.consent_receipt_hash,
                "nonce": self.nonce,
                "expires_at": self.expires_at,
                "appshell_epoch": self.appshell_epoch,
                "effect_id": self.effect_id,
                "arguments_hash": self.arguments_hash,
                "endpoint_digest": self.endpoint_digest,
            }
        )


class NetworkEgressPermitIssuer:
    """Issues domain-separated, single-use network egress permits."""

    _DEFAULT_MAX_SPENT_NONCES = 10_000

    def __init__(
        self,
        *,
        key: bytes | None = None,
        ttl_seconds: float = 60.0,
        max_spent_nonces: int | None = None,
    ) -> None:
        if ttl_seconds <= 0:
            raise ValueError("permit ttl_seconds must be positive")
        limit = (
            self._DEFAULT_MAX_SPENT_NONCES if max_spent_nonces is None else int(max_spent_nonces)
        )
        if limit < 1:
            raise ValueError("max_spent_nonces must be positive")
        self._key = key if key is not None else os.urandom(32)
        if len(self._key) < 32:
            raise ValueError("permit key must be at least 32 bytes")
        self._ttl_seconds = float(ttl_seconds)
        self._max_spent_nonces = limit
        self._spent_nonces: dict[str, float] = {}
        self._lock = threading.Lock()

    def _mac(self, permit: NetworkEgressPermit) -> str:
        return hmac.new(self._key, permit._payload().encode("utf-8"), hashlib.sha256).hexdigest()

    def issue(
        self,
        *,
        kind: str,
        attempt_id: str,
        attempt_hash: str,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        channel: str,
        product_id: str,
        endpoint_generation: str,
        credential_generation: str,
        payload_digest: str,
        provenance_digest: str,
        consent_receipt_hash: str,
        appshell_epoch: str | None = None,
        effect_id: str = "",
        arguments_hash: str = "",
        endpoint_digest: str = "",
    ) -> NetworkEgressPermit:
        permit = NetworkEgressPermit(
            kind=kind,
            attempt_id=attempt_id,
            attempt_hash=attempt_hash,
            owner_key_hash=owner_key_hash,
            session_id=session_id,
            run_id=run_id,
            channel=channel,
            product_id=product_id,
            endpoint_generation=endpoint_generation,
            credential_generation=credential_generation,
            payload_digest=payload_digest,
            provenance_digest=provenance_digest,
            consent_receipt_hash=consent_receipt_hash,
            nonce=secrets.token_hex(16),
            expires_at=time.time() + self._ttl_seconds,
            mac="",
            appshell_epoch=appshell_epoch,
            effect_id=effect_id,
            arguments_hash=arguments_hash,
            endpoint_digest=endpoint_digest,
        )
        return replace(permit, mac=self._mac(permit))

    def verify_and_consume(
        self,
        permit: NetworkEgressPermit | Any,
        *,
        kind: str,
        attempt_id: str,
        attempt_hash: str,
        owner_key_hash: str,
        session_id: str,
        run_id: str,
        channel: str,
        product_id: str,
        endpoint_generation: str,
        credential_generation: str,
        payload_digest: str,
        provenance_digest: str,
        consent_receipt_hash: str,
        appshell_epoch: str | None = None,
        effect_id: str = "",
        arguments_hash: str = "",
        endpoint_digest: str = "",
    ) -> None:
        if not isinstance(permit, NetworkEgressPermit):
            raise NetworkEgressPermitError("network permit missing or not a NetworkEgressPermit")
        expected_mac = self._mac(permit)
        if not hmac.compare_digest(expected_mac, permit.mac):
            raise NetworkEgressPermitError("network permit MAC mismatch")
        if time.time() >= permit.expires_at:
            raise NetworkEgressPermitError("network permit expired")
        if permit.kind != kind:
            raise NetworkEgressPermitError("network permit kind mismatch")
        if not hmac.compare_digest(permit.attempt_id, attempt_id):
            raise NetworkEgressPermitError("network permit attempt_id mismatch")
        if not hmac.compare_digest(permit.attempt_hash, attempt_hash):
            raise NetworkEgressPermitError("network permit attempt_hash mismatch")
        if not hmac.compare_digest(permit.owner_key_hash, owner_key_hash):
            raise NetworkEgressPermitError("network permit owner mismatch")
        if not hmac.compare_digest(permit.session_id, session_id):
            raise NetworkEgressPermitError("network permit session mismatch")
        if not hmac.compare_digest(permit.run_id, run_id):
            raise NetworkEgressPermitError("network permit run mismatch")
        if permit.channel != channel:
            raise NetworkEgressPermitError("network permit channel mismatch")
        if permit.product_id != product_id:
            raise NetworkEgressPermitError("network permit product mismatch")
        if not hmac.compare_digest(permit.endpoint_generation, endpoint_generation):
            raise NetworkEgressPermitError("network permit endpoint generation mismatch")
        if not hmac.compare_digest(permit.credential_generation, credential_generation):
            raise NetworkEgressPermitError("network permit credential generation mismatch")
        if not hmac.compare_digest(permit.payload_digest, payload_digest):
            raise NetworkEgressPermitError("network permit payload digest mismatch")
        if not hmac.compare_digest(permit.provenance_digest, provenance_digest):
            raise NetworkEgressPermitError("network permit provenance mismatch")
        if not hmac.compare_digest(permit.consent_receipt_hash, consent_receipt_hash):
            raise NetworkEgressPermitError("network permit consent receipt mismatch")
        if (permit.appshell_epoch or "") != (appshell_epoch or ""):
            raise NetworkEgressPermitError("network permit epoch mismatch")
        if not _bound_str_eq(permit.effect_id, effect_id):
            raise NetworkEgressPermitError("network permit effect_id mismatch")
        if not _bound_str_eq(permit.arguments_hash, arguments_hash):
            raise NetworkEgressPermitError("network permit arguments_hash mismatch")
        if not _bound_str_eq(permit.endpoint_digest, endpoint_digest):
            raise NetworkEgressPermitError("network permit endpoint digest mismatch")
        with self._lock:
            now = time.time()
            if now >= permit.expires_at:
                raise NetworkEgressPermitError("network permit expired")
            expired = [nonce for nonce, expires_at in self._spent_nonces.items() if expires_at <= now]
            for nonce in expired:
                del self._spent_nonces[nonce]
            existing_expiry = self._spent_nonces.get(permit.nonce)
            if existing_expiry is not None and existing_expiry > now:
                raise NetworkEgressPermitError("network permit replayed")
            if len(self._spent_nonces) >= self._max_spent_nonces:
                raise NetworkEgressPermitError("network permit spent nonce capacity exhausted")
            self._spent_nonces[permit.nonce] = permit.expires_at
