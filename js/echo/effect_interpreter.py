"""Trusted adapters for side effects emitted inside an Echo runtime context."""

from __future__ import annotations

import asyncio
import json
import secrets
import time
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from js.connectors.contracts import (
    ConnectorExecutionRequestV1,
    ConnectorRunOutcomeV1,
    canonical_params_digest,
)
from js.connectors.manager import ConnectorManager
from js.echo.turn_context import (
    RuntimeContext,
    reset_current_owner_key_hash,
    reset_runtime_context,
    runtime_context_error,
    set_current_owner_key_hash,
    set_runtime_context,
)
from js.models.providers import ChatMessage, ChatResponse
from js.security.approvals import ApprovalQueue
from js.tools.registry import ToolResult
from js.utils.log import get_logger

if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Awaitable, Callable

    from js.models.stream_events import StreamEvent

logger = get_logger("js.echo.effect_interpreter")


def _new_d1_lease_id(prefix: str, run_id: str, *parts: object) -> str:
    """Mint a unique D1 lease id.

    ``id(effect)`` is unsafe here: CPython may recycle object addresses after GC,
    which collides with EffectAuthority's single-use ``lease already issued`` gate
    across retries / multi-turn runs that share ``run_id``.
    """

    stable = ":".join(str(part) for part in parts if part not in (None, ""))
    nonce = secrets.token_hex(8)
    if stable:
        return f"{prefix}:{run_id}:{stable}:{nonce}"
    return f"{prefix}:{run_id}:{nonce}"


@dataclass(frozen=True)
class ModelEffect:
    """One authorized model invocation."""

    messages: tuple[ChatMessage, ...]
    model: str | None = None
    tools_schema: tuple[dict[str, Any], ...] = ()
    attachment_manifest: tuple[dict[str, Any], ...] = ()
    temperature: float = 0.7
    max_tokens: int | None = None
    before_model_attempt: Callable[[], None] | None = None
    completion_budget_callback: Callable[[int], None] | None = None


@dataclass(frozen=True)
class ToolEffect:
    """One authorized tool invocation with a stable serialized input."""

    tool_name: str
    arguments_json: str
    tool_call_id: str = ""
    user_input: str = ""
    allowed_tools: tuple[str, ...] = ()

    @classmethod
    def from_arguments(
        cls,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        tool_call_id: str = "",
        user_input: str = "",
        allowed_tools: tuple[str, ...] = (),
    ) -> ToolEffect:
        return cls(
            tool_name=tool_name,
            arguments_json=json.dumps(
                dict(arguments),
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            ),
            tool_call_id=tool_call_id,
            user_input=user_input,
            allowed_tools=allowed_tools,
        )


class EffectInterpreter:
    """The only adapter allowed to invoke model and tool side effects."""

    def __init__(
        self,
        agent: Any,
        *,
        runtime_authority: Any | None = None,
        connector_manager: ConnectorManager | None = None,
        dispatch_issuer: Any | None = None,
        effect_authority: Any | None = None,
    ) -> None:
        self._agent = agent
        self._runtime_authority = runtime_authority
        self._connector_manager = connector_manager
        self._dispatch_issuer = dispatch_issuer
        self._effect_authority = effect_authority

    async def execute_model(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
    ) -> ChatResponse:
        self._validate_context(context, effect_kind="model")
        operation = self._begin_effect_operation(context, effect_kind="model")
        try:
            return await self._execute_model_admitted(effect, context)
        finally:
            self._finish_effect_operation(operation)

    async def _execute_model_admitted(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
    ) -> ChatResponse:
        authorized_chat = getattr(self._agent, "authorized_model_chat", None)
        if not callable(authorized_chat):
            raise RuntimeError("Echo model effect requires authorized_model_chat")

        receipt = self._admit_d1(
            effect_class="model",
            context=context,
            lease_id=_new_d1_lease_id("model", context.run_id),
            grants=frozenset(),
        )
        from js.echo.effect_bind import reset_effect_exec_receipt, set_effect_exec_receipt

        bind = set_effect_exec_receipt(receipt)
        owner_token = set_current_owner_key_hash(context.owner_key_hash)
        context_token = set_runtime_context(context)
        try:
            response = await self._call_before_deadline(
                lambda: authorized_chat(
                    messages=list(effect.messages),
                    tenant_id=context.owner_key_hash,
                    run_id=context.run_id,
                    session_id=context.session_id or "",
                    model=effect.model,
                    tools=list(effect.tools_schema) or None,
                    attachment_manifest=effect.attachment_manifest,
                    temperature=effect.temperature,
                    max_tokens=effect.max_tokens,
                    budget_callback=effect.before_model_attempt,
                    completion_budget_callback=effect.completion_budget_callback,
                ),
                context,
            )
            if not isinstance(response, ChatResponse):
                raise TypeError("authorized model adapter returned an invalid response")
            return response
        finally:
            reset_runtime_context(context_token)
            reset_current_owner_key_hash(owner_token)
            reset_effect_exec_receipt(bind)

    async def execute_model_stream(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
        *,
        before_model_call: Callable[..., Awaitable[Any]],
        after_model_call: Callable[..., Awaitable[None]],
    ) -> AsyncIterator[StreamEvent]:
        """Stream one model effect through the router under a bound runtime context.

        This is the sole call site allowed to invoke
        ``agent.router.chat_stream_events``. Context is restored in ``finally``
        even when the consumer stops early or the generator raises.
        """
        self._validate_context(context, effect_kind="model")
        operation = self._begin_effect_operation(context, effect_kind="model_stream")
        try:
            async for event in self._execute_model_stream_admitted(
                effect,
                context,
                before_model_call=before_model_call,
                after_model_call=after_model_call,
            ):
                yield event
        finally:
            self._finish_effect_operation(operation)

    async def _execute_model_stream_admitted(
        self,
        effect: ModelEffect,
        context: RuntimeContext,
        *,
        before_model_call: Callable[..., Awaitable[Any]],
        after_model_call: Callable[..., Awaitable[None]],
    ) -> AsyncIterator[StreamEvent]:
        router = getattr(self._agent, "router", None)
        chat_stream_events = getattr(router, "chat_stream_events", None)
        if not callable(chat_stream_events):
            raise RuntimeError("Echo model stream effect requires router.chat_stream_events")

        # The router must be gated by unforgeable single-use permits issued by
        # this runtime; a rebindable callback API is rejected outright.
        if getattr(router, "bind_echo_callbacks", None) is not None:
            raise RuntimeError(
                "router exposes a rebindable callback API; refusing to run the "
                "Echo model stream gate without unforgeable permits"
            )
        issuer = getattr(self._agent, "_model_permit_issuer", None)
        if issuer is None:
            # The verifier installed on the router is the same runtime-owned
            # issuer (the unforgeability lives in the HMAC key, not in where
            # the object is referenced from).  Accept it as the permit source.
            issuer = getattr(router, "_permit_verifier", None)
        if issuer is None or not callable(getattr(issuer, "issue", None)):
            raise RuntimeError("Echo model stream effect requires the runtime permit issuer")

        self._admit_d1(
            effect_class="model",
            context=context,
            lease_id=_new_d1_lease_id("model-stream", context.run_id),
            grants=frozenset(),
        )

        def _permit_grant(
            decision: Any,
            call_messages: list[ChatMessage],
            call_tools: Any,
        ) -> Any:
            return issuer.issue(
                provider_name=str(getattr(decision, "provider_name", "")),
                model=str(getattr(decision, "model", effect.model or "default")),
                messages=call_messages,
                tools=call_tools,
                owner_key_hash=context.owner_key_hash,
                session_id=context.session_id or "",
                run_id=context.run_id,
            )

        stream = chat_stream_events(
            messages=list(effect.messages),
            model=effect.model,
            tools=list(effect.tools_schema) or None,
            temperature=effect.temperature,
            max_tokens=effect.max_tokens,
            before_model_call=before_model_call,
            after_model_call=after_model_call,
            permit_grant=_permit_grant,
        )
        iterator = aiter(stream)
        try:
            while True:
                owner_token = set_current_owner_key_hash(context.owner_key_hash)
                context_token = set_runtime_context(context)
                try:
                    event = await self._call_before_deadline(
                        lambda: anext(iterator),
                        context,
                    )
                except StopAsyncIteration:
                    return
                finally:
                    reset_runtime_context(context_token)
                    reset_current_owner_key_hash(owner_token)
                yield event
        finally:
            # Close the provider stream directly.  Routing the close through
            # ``_call_before_deadline`` meant that on cancellation or an
            # exceeded deadline the guard raised before ``close`` ever ran,
            # leaking the provider connection.  Closing is best-effort: a
            # failure here must never mask the in-flight exception.  This also
            # runs when the consumer stops early and GeneratorExit is thrown in
            # at the ``yield`` above — awaiting in a generator's finally during
            # aclose() is legal as long as nothing is yielded.
            close = getattr(stream, "aclose", None)
            if callable(close):
                owner_token = set_current_owner_key_hash(context.owner_key_hash)
                context_token = set_runtime_context(context)
                try:
                    try:
                        await close()
                    except Exception:
                        logger.debug("Echo provider stream close failed", exc_info=True)
                finally:
                    reset_runtime_context(context_token)
                    reset_current_owner_key_hash(owner_token)

    async def execute_tool(
        self,
        effect: ToolEffect,
        context: RuntimeContext,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> tuple[ChatMessage, ToolResult]:
        self._validate_context(context, effect_kind="tool")
        operation = self._begin_effect_operation(context, effect_kind="tool")
        try:
            return await self._execute_tool_admitted(effect, context, progress_callback)
        finally:
            self._finish_effect_operation(operation)

    async def _execute_tool_admitted(
        self,
        effect: ToolEffect,
        context: RuntimeContext,
        progress_callback: Callable[[str, ToolResult], Awaitable[None]] | None = None,
    ) -> tuple[ChatMessage, ToolResult]:
        if not effect.tool_name:
            raise ValueError("Echo tool effect requires a tool name")

        from js.echo.plan_commit.narrowing import deny_write_egress_if_blocked

        deny_write_egress_if_blocked(effect.tool_name)

        context_tools = set(context.capabilities)
        effect_tools = set(effect.allowed_tools)
        allowed_tools = context_tools & effect_tools
        if not allowed_tools or effect.tool_name not in allowed_tools:
            raise PermissionError("Echo tool effect is outside the runtime capability set")

        execute = getattr(self._agent, "_execute_tool_call", None)
        if not callable(execute):
            raise RuntimeError("Echo tool effect requires the leased tool executor")

        from js.echo.effect_bind import reset_effect_exec_receipt, set_effect_exec_receipt
        from js.echo.effect_grants import assert_grants_cover_tool, grants_for_effect_tool

        resource_scope = " ".join(str(root) for root in getattr(context, "fs_roots", ()) or ())
        context_taint = int(getattr(context, "taint", 0) or 0)
        grants = grants_for_effect_tool(
            effect.tool_name,
            resource_scope=resource_scope,
            context_taint=context_taint,
        )
        assert_grants_cover_tool(effect.tool_name, grants, context_taint=context_taint)
        receipt = self._admit_d1(
            effect_class="tool",
            context=context,
            lease_id=_new_d1_lease_id(
                "tool",
                context.run_id,
                effect.tool_name,
                effect.tool_call_id,
            ),
            grants=grants,
            tool_name=effect.tool_name,
        )

        tool_call = {
            "id": effect.tool_call_id,
            "type": "function",
            "function": {
                "name": effect.tool_name,
                "arguments": effect.arguments_json,
            },
        }
        bind = set_effect_exec_receipt(receipt)
        owner_token = set_current_owner_key_hash(context.owner_key_hash)
        context_token = set_runtime_context(context)
        try:
            result = await self._call_before_deadline(
                lambda: execute(
                    tool_call,
                    context.session_id or "default",
                    context.run_id,
                    effect.user_input,
                    progress_callback,
                    allowed_tools=allowed_tools,
                    owner_key_hash=context.owner_key_hash,
                ),
                context,
            )
            if (
                not isinstance(result, tuple)
                or len(result) != 2
                or not isinstance(result[0], ChatMessage)
                or not isinstance(result[1], ToolResult)
            ):
                raise TypeError("leased tool adapter returned an invalid result")
            return result
        finally:
            reset_runtime_context(context_token)
            reset_current_owner_key_hash(owner_token)
            reset_effect_exec_receipt(bind)

    async def execute_connector(
        self,
        request: ConnectorExecutionRequestV1,
        *,
        params: Mapping[str, Any],
        context: RuntimeContext,
    ) -> ConnectorRunOutcomeV1:
        """Execute one connector only under the owning signed Echo runtime."""

        self._validate_context(context, effect_kind="connector")
        operation = self._begin_effect_operation(context, effect_kind="connector")
        try:
            return await self._execute_connector_admitted(
                request,
                params=params,
                context=context,
                operation=operation,
            )
        finally:
            self._finish_effect_operation(operation)

    async def _execute_connector_admitted(
        self,
        request: ConnectorExecutionRequestV1,
        *,
        params: Mapping[str, Any],
        context: RuntimeContext,
        operation: Any = None,
    ) -> ConnectorRunOutcomeV1:
        """Connector exec: single D1 authority chain (no lease_authority dual ticket)."""

        if type(request) is not ConnectorExecutionRequestV1:
            raise TypeError("connector request must be exact ConnectorExecutionRequestV1")
        if not isinstance(params, Mapping) or isinstance(params, (str, bytes, bytearray)):
            raise TypeError("connector params must be a mapping")
        manager = self._connector_manager
        if type(manager) is not ConnectorManager:
            raise RuntimeError("Echo connector manager authority is unavailable")
        task_ref = context.task_ref
        if task_ref is None or task_ref != request.task_ref:
            raise PermissionError("connector task_ref does not match signed runtime context")
        if (
            request.task_ref.legacy_product_id != context.product_id
            or request.task_ref.owner != context.owner_key_hash
            or request.task_ref.session != context.session_id
            or request.task_ref.run != context.run_id
        ):
            raise PermissionError("connector task_ref exceeds signed runtime identity")

        actual_params = dict(params)
        if canonical_params_digest(actual_params) != request.params_digest:
            raise PermissionError("connector params do not match authority binding")
        grant = request.directory_grant
        if request.connection.ref.connector_type in {"local_import", "local_publish"}:
            if grant is None:
                raise PermissionError("local connector requires a directory grant")
            if grant.root == "/":
                raise PermissionError("connector directory grant cannot be filesystem root")
            grant_path = Path(grant.root)
            runtime_roots = tuple(Path(root).resolve(strict=False) for root in context.fs_roots)
            if not any(
                grant_path == root or grant_path.is_relative_to(root) for root in runtime_roots
            ):
                raise PermissionError("connector directory grant exceeds runtime filesystem roots")

        expected_tool = (
            f"connector.{request.connection.ref.connector_type}.{request.operation}"
        )
        if not getattr(request.lease, "lease_id", ""):
            raise PermissionError("connector effect requires non-empty lease_id")

        approvals: ApprovalQueue | None = None
        approval_kwargs: dict[str, Any] | None = None
        if request.operation == "write":
            approvals = getattr(self._agent, "approvals", None)
            if type(approvals) is not ApprovalQueue or request.approval_id is None:
                raise PermissionError("connector write approval authority is unavailable")
            approval_arguments = {
                "authority_binding_hash": request.authority_binding_hash(),
                "scope": request.scope,
            }
            approval_kwargs = {
                "owner_key_hash": request.task_ref.owner,
                "session_id": request.task_ref.session,
                "run_id": request.task_ref.run,
                "tool_name": expected_tool,
                "arguments_hash": approvals.arguments_hash(approval_arguments),
                "require_manual": True,
            }
            approvals.validate_approved_binding(request.approval_id, **approval_kwargs)

        from js.echo.effect_bind import (
            require_effect_exec_receipt,
            reset_effect_exec_receipt,
            set_effect_exec_receipt,
        )
        from js.echo.effect_grants import assert_grants_cover_tool, grants_for_effect_tool

        # Frozen D8 / D1: one admit → bind → require → dispatch. No second ticket.
        # Stable id from the sealed CapabilityLease so replay is single-use denied.
        d1_lease_id = (
            f"connector:{context.run_id}:{request.lease.lease_id}:{request.lease.nonce}"
        )
        context_taint = int(getattr(context, "taint", 0) or 0)
        d1_grants = grants_for_effect_tool(
            expected_tool,
            resource_scope=str(getattr(request, "scope", "") or ""),
            context_taint=context_taint,
        )
        assert_grants_cover_tool(expected_tool, d1_grants, context_taint=context_taint)
        d1_receipt = self._admit_d1(
            effect_class="connector",
            context=context,
            lease_id=d1_lease_id,
            grants=d1_grants,
            tool_name=expected_tool,
        )
        d1_bind = set_effect_exec_receipt(d1_receipt)
        try:
            require_effect_exec_receipt()

            if approvals is not None and approval_kwargs is not None:
                assert request.approval_id is not None
                approvals.consume_approved_binding(request.approval_id, **approval_kwargs)

            if self._dispatch_issuer is None:
                raise RuntimeError("connector_runtime_authority_required")
            context_fingerprint = ""
            if self._runtime_authority is not None:
                context_fingerprint = self._runtime_authority._context_fingerprint(context)
            capability = self._dispatch_issuer.issue(
                authority_hash=request.authority_binding_hash(),
                context_fingerprint=context_fingerprint,
                appshell_operation_id=(operation.operation_id if operation else None),
                approval_claim_receipt_hash=None,
                lease_consume_receipt_hash=d1_receipt.consume_receipt_hash,
                connector_type=request.connection.ref.connector_type,
                operation=request.operation,
            )
            require_effect_exec_receipt()
            result = await manager._dispatch_authorized(
                request,
                params=actual_params,
                capability=capability,
            )
            error_code = None if result.success else (result.error or "connector_failed")
            return ConnectorRunOutcomeV1(
                success=result.success,
                connector_type=result.connector_type,
                effects=result.effects,
                artifact_refs=result.artifact_refs,
                attention_items=(),
                receipt_id=d1_receipt.consume_receipt_hash,
                error_code=error_code,
            )
        finally:
            reset_effect_exec_receipt(d1_bind)


    def _admit_d1(
        self,
        *,
        effect_class: str,
        context: RuntimeContext,
        lease_id: str,
        grants: frozenset[str],
        tool_name: str | None = None,
    ) -> Any:
        from echo_core.effect_authority import EffectAuthorityError, EffectProposal

        from js.echo.effect_grants import assert_grants_cover_tool

        authority = self._effect_authority
        if authority is None:
            authority = getattr(self._runtime_authority, "effect_authority", None)
        if authority is None:
            raise EffectAuthorityError(
                "EffectAuthority is not wired; refuse ambient Interpreter.exec"
            )
        if effect_class in {"tool", "connector"} and not lease_id:
            raise EffectAuthorityError("tool-class effect requires non-empty lease_id")
        if effect_class == "tool":
            if not tool_name:
                raise EffectAuthorityError("tool name required to admit tool effect")
            assert_grants_cover_tool(tool_name, grants)
        elif effect_class == "connector" and tool_name:
            assert_grants_cover_tool(tool_name, grants)
        proposal = EffectProposal(
            owner=context.owner_key_hash or "owner",
            session=context.session_id or "session",
            run=context.run_id or "run",
            effect_class=effect_class,
            grants=grants,
            budget=1,
        )
        receipt = authority.admit_effect(proposal, lease_id=lease_id)
        authority.require_exec(lease_id)
        return receipt

    @staticmethod
    async def _call_before_deadline(
        call: Callable[[], Awaitable[Any]],
        context: RuntimeContext,
    ) -> Any:
        error = runtime_context_error(context)
        if error is not None:
            if "cancelled" in error:
                raise asyncio.CancelledError("Echo runtime context is cancelled")
            if "deadline" in error:
                raise TimeoutError("Echo runtime context deadline exceeded")
            raise ValueError(error)

        assert context.deadline_ms is not None
        remaining = (context.deadline_ms - time.monotonic() * 1000) / 1000
        if remaining <= 0:
            raise TimeoutError("Echo runtime context deadline exceeded")

        timeout = asyncio.timeout(remaining)
        try:
            async with timeout:
                return await call()
        except TimeoutError as exc:
            if timeout.expired():
                raise TimeoutError("Echo runtime context deadline exceeded") from exc
            raise

    def _validate_context(
        self,
        context: RuntimeContext,
        *,
        effect_kind: str,
    ) -> None:
        authority = self._runtime_authority
        validate = getattr(authority, "validate_effect_context", None)
        if (
            authority is None
            or getattr(self._agent, "echo_runtime", None) is not authority
            or not callable(validate)
        ):
            raise RuntimeError("Echo effect runtime authority is unavailable")
        validate(context, effect_kind=effect_kind)
        error = runtime_context_error(context)
        if error is not None:
            raise ValueError(error)
        try:
            from js.utils.metrics import bind_effect_ids

            bind_effect_ids(
                kind=effect_kind,
                effect_id=context.run_id,
                outbox_id=context.session_id,
                lease_id=context.owner_key_hash,
            )
        except Exception:
            pass

    def _begin_effect_operation(
        self,
        context: RuntimeContext,
        *,
        effect_kind: str,
    ) -> Any | None:
        if context.appshell_epoch_binding is None:
            return None
        begin = getattr(self._runtime_authority, "begin_effect_operation", None)
        if not callable(begin):
            raise RuntimeError("AppShell effect operation authority is unavailable")
        return begin(context, effect_kind=effect_kind)

    def _finish_effect_operation(self, operation: Any | None) -> None:
        if operation is None:
            return
        finish = getattr(self._runtime_authority, "finish_effect_operation", None)
        if not callable(finish):
            raise RuntimeError("AppShell effect operation authority is unavailable")
        finish(operation)


__all__ = ["EffectInterpreter", "ModelEffect", "ToolEffect"]
