"""B2B-C: connector HTTP egress consent, unified with B2A write approval."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from js.connectors.base import ConnectorBase, ConnectorResult
from js.connectors.contracts import ConnectorExecutionRequestV1, canonical_params_digest
from js.echo.mode_contract import (
    AppMode,
    ConnectionRefV1,
    ConnectorManifestV1,
    DirectoryGrantV1,
)
from js.security.approvals import ApprovalDecisionType
from tests.test_b2c_non_model_egress import (
    SYNTH_BODY,
    SYNTH_QUERY,
    SideEffects,
    _assert_zero_network,
    _egress_mod,
    _require,
)
from tests.test_r4_connector_boundary import _runtime_bundle


class HttpSpyConnector(ConnectorBase):
    def __init__(self, effects: SideEffects) -> None:
        super().__init__(
            ConnectorManifestV1(
                connector_type="http_spy",
                capabilities=("read", "write"),
                read_scopes=("remote",),
                write_scopes=("publish",),
                approval_policy="explicit",
            )
        )
        self.effects = effects
        self.read_calls = 0
        self.write_calls = 0
        self.seen_params: list[dict[str, Any]] = []

    async def _read_authorized(  # type: ignore[no-untyped-def,override]
        self, scope: str, *, params=None, directory_grant=None, context_binding=None
    ) -> ConnectorResult:
        self.read_calls += 1
        self.effects.http += 1
        self.effects.order.append("handler")
        self.seen_params.append(dict(params or {}))
        return ConnectorResult(connector_type="http_spy", success=True)

    async def _write_authorized(  # type: ignore[no-untyped-def,override]
        self, scope: str, *, params=None, directory_grant=None, context_binding=None
    ) -> ConnectorResult:
        self.write_calls += 1
        self.effects.http += 1
        self.effects.order.append("handler")
        self.seen_params.append(dict(params or {}))
        return ConnectorResult(connector_type="http_spy", success=True)


def _install_spy(runtime: Any, spy: HttpSpyConnector) -> None:
    from js.models.permit import NetworkEgressPermitIssuer

    manager = runtime.effects._connector_manager
    manager._sealed = False
    manager._register_for_composition(spy)
    manager._seal()
    runtime._agent._network_permit_issuer = NetworkEgressPermitIssuer()
    if not hasattr(runtime._agent, "_egress_consent_broker"):
        runtime._agent._egress_consent_broker = None


def _network_fields(params: dict[str, Any], host: str = "api.example.test") -> dict[str, Any]:
    from js.security.egress import endpoint_generation_of

    raw_url = params.get("url")
    if type(raw_url) is not str or not raw_url.strip():
        raw_url = f"https://{host}/"
    return {
        "network_kind": "connector_egress",
        "endpoint": host if ":" in host else f"{host}:443",
        "payload_digest": canonical_params_digest(params).removeprefix("sha256:"),
        "endpoint_generation": endpoint_generation_of(raw_url),
    }


def _http_request(
    agent: Any,
    context: Any,
    authority: Any,
    *,
    params: dict[str, Any],
    operation: str,
    include_network_fields: bool = True,
    approve: bool = True,
) -> ConnectorExecutionRequestV1:
    from js.connectors import contracts

    manifest = spy_manifest = ConnectorManifestV1(
        connector_type="http_spy",
        capabilities=("read", "write"),
        read_scopes=("remote",),
        write_scopes=("publish",),
        approval_policy="explicit",
    )
    del spy_manifest
    connection = contracts.ConnectionRefV2(
        ref=ConnectionRefV1(
            mode=AppMode.PERSONAL,
            owner="owner-a",
            workspace=None,
            connector_type="http_spy",
            connection_id="http-a",
            authorized_by="owner-a",
        ),
        manifest_digest=manifest.canonical_hash(),
        vault_ref=None,
    )
    grant = DirectoryGrantV1(
        mode=AppMode.PERSONAL,
        workspace=None,
        root=str(context.workspace),
    )
    tool_name = f"connector.http_spy.{operation}"
    placeholder = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name=tool_name,
        args_schema="sha256:" + "0" * 64,
        resource_scope="connection:http-a:" + ("publish" if operation == "write" else "remote"),
        fs_roots=(grant.root,),
        network_policy="allow",
        network_hosts=("api.example.test",),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    request = ConnectorExecutionRequestV1(
        task_ref=context.task_ref,
        connection=connection,
        manifest=manifest,
        operation=operation,  # type: ignore[arg-type]
        scope="publish" if operation == "write" else "remote",
        params_digest=canonical_params_digest(params),
        directory_grant=grant,
        approval_id=None if operation == "read" else "pending",
        lease=placeholder,
    )
    approval_id = None
    if operation == "write":
        arguments: dict[str, Any] = {
            "authority_binding_hash": request.authority_binding_hash(),
            "scope": "publish",
        }
        if include_network_fields:
            arguments.update(_network_fields(params))
        pending = agent.approvals.request_decision(
            tool_name,
            arguments,
            context="web",
            session_id="session-a",
            run_id="run-a",
            owner_key_hash="owner-a",
            queue_if_unhandled=True,
        )
        if approve:
            agent.approvals.decide(
                pending.request_id,
                ApprovalDecisionType.APPROVE,
                owner_key_hash="owner-a",
            )
        approval_id = pending.request_id
    lease = authority.issue(
        product_id="js-agent",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name=tool_name,
        args_schema=request.authority_binding_hash(),
        resource_scope="connection:http-a:" + ("publish" if operation == "write" else "remote"),
        fs_roots=(grant.root,),
        network_policy="allow",
        network_hosts=("api.example.test",),
        max_bytes=10 * 1024 * 1024,
        max_duration_ms=30_000,
        max_invocations=1,
        ttl_ms=60_000,
    )
    return dataclasses_replace(request, lease=lease, approval_id=approval_id)


def dataclasses_replace(request: ConnectorExecutionRequestV1, **kwargs: Any) -> ConnectorExecutionRequestV1:
    import dataclasses

    return dataclasses.replace(request, **kwargs)


@pytest.mark.asyncio
async def test_11_dangerous_write_is_one_product_decision(tmp_path: Path) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    original_request = agent.approvals.request_decision

    calls: list[str] = []

    def counting_request(tool_name: str, *args: Any, **kwargs: Any) -> Any:
        calls.append(tool_name)
        return original_request(tool_name, *args, **kwargs)

    agent.approvals.request_decision = counting_request  # type: ignore[method-assign]
    request = _http_request(agent, context, authority, params=params, operation="write")
    assert calls.count("connector.http_spy.write") == 1
    assert calls.count("connector_egress") == 0
    pending_tools = [req.tool_name for req in agent.approvals._pending.values()] if hasattr(agent.approvals, "_pending") else []
    assert "connector_egress" not in pending_tools
    outcome = await runtime.execute_connector_effect(request, params=params, context=context)
    assert outcome.success is True
    assert spy.write_calls == 1
    assert calls.count("connector.http_spy.write") == 1
    assert calls.count("connector_egress") == 0


@pytest.mark.asyncio
async def test_12_b2a_claim_binds_same_final_args(tmp_path: Path) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request = _http_request(agent, context, authority, params=params, operation="write")
    proof = agent.approvals.validate_approved_binding(
        request.approval_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.http_spy.write",
        arguments_hash=agent.approvals.arguments_hash(
            {
                "authority_binding_hash": request.authority_binding_hash(),
                "scope": "publish",
                **_network_fields(params),
            }
        ),
        require_manual=True,
    )
    assert proof.request_id == request.approval_id


@pytest.mark.asyncio
async def test_13_cas_loser_dispatch_zero(tmp_path: Path) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request = _http_request(agent, context, authority, params=params, operation="write")
    agent.approvals.consume_approved_binding(
        request.approval_id,
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        tool_name="connector.http_spy.write",
        arguments_hash=agent.approvals.arguments_hash(
            {
                "authority_binding_hash": request.authority_binding_hash(),
                "scope": "publish",
                **_network_fields(params),
            }
        ),
        require_manual=True,
    )
    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert spy.write_calls == 0
    assert effects.http == 0


@pytest.mark.asyncio
async def test_claimed_now_false_does_not_dispatch(tmp_path: Path) -> None:
    from dataclasses import replace

    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request = _http_request(agent, context, authority, params=params, operation="write")
    original = agent.approvals.consume_approved_binding

    def loser(*args: Any, **kwargs: Any) -> Any:
        proof = original(*args, **kwargs)
        return replace(proof, claimed_now=False)

    agent.approvals.consume_approved_binding = loser  # type: ignore[method-assign]
    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert spy.write_calls == 0
    assert effects.http == 0


@pytest.mark.asyncio
async def test_14_nested_params_mutation_after_consent(tmp_path: Path) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params: dict[str, Any] = {"nested": {"q": SYNTH_QUERY}, "url": "https://api.example.test/read"}
    request = _http_request(agent, context, authority, params=params, operation="write")
    params["nested"]["q"] = "MUTATED"
    with pytest.raises((PermissionError, ValueError)):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert spy.write_calls == 0


@pytest.mark.asyncio
async def test_15_read_connector_without_consent_transport_zero(tmp_path: Path) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"q": SYNTH_QUERY, "url": "https://api.example.test/search"}
    request = _http_request(agent, context, authority, params=params, operation="read")
    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert spy.read_calls == 0
    assert effects.http == 0
    _assert_zero_network(effects)


@pytest.mark.asyncio
async def test_16_forged_or_missing_receipt_zero_handler(tmp_path: Path) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request = _http_request(agent, context, authority, params=params, operation="write")
    forged = dataclasses_replace(request, approval_id="forged-approval")
    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(forged, params=params, context=context)
    assert spy.write_calls == 0


@pytest.mark.asyncio
async def test_17_redirect_retry_reconnect_need_new_auth(tmp_path: Path) -> None:
    module = _egress_mod()
    build = _require(module, "build_network_egress_attempt")
    kind = _require(module, "NetworkEgressKind")
    identity_cls = _require(module, "EgressIdentityV1")
    identity = identity_cls(
        product_id="js-agent",
        channel="search",
        owner_key_hash="owner-a",
        session_id="session-a",
        run_id="run-a",
        appshell_epoch="1",
    )
    first = build(
        identity=identity,
        kind=kind.CONNECTOR,
        target_identity="http_spy",
        endpoint_url="https://api.example.test/v1",
        method="POST",
        payload={"body": SYNTH_BODY},
        provenance={
            "schema": "network-egress-provenance-v1",
            "kind": "connector_egress",
            "source": "connector",
            "tool_name": "connector.http_spy.write",
        },
        credential_generation="none",
    )
    redirected = build(
        identity=identity,
        kind=kind.CONNECTOR,
        target_identity="http_spy",
        endpoint_url="https://evil.example.test/v1",
        method="POST",
        payload={"body": SYNTH_BODY},
        provenance={
            "schema": "network-egress-provenance-v1",
            "kind": "connector_egress",
            "source": "connector",
            "tool_name": "connector.http_spy.write",
        },
        credential_generation="none",
    )
    assert first.attempt_id != redirected.attempt_id
    assert first.endpoint_generation != redirected.endpoint_generation


@pytest.mark.asyncio
async def test_18_write_approved_but_egress_binding_missing_handler_zero(
    tmp_path: Path,
) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request = _http_request(
        agent,
        context,
        authority,
        params=params,
        operation="write",
        include_network_fields=False,
    )
    with pytest.raises(PermissionError):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert spy.write_calls == 0


@pytest.mark.asyncio
async def test_19_egress_ok_but_claim_loser_handler_zero(tmp_path: Path) -> None:
    await test_13_cas_loser_dispatch_zero(tmp_path)


@pytest.mark.asyncio
async def test_20_raw_body_not_logged(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    caplog.set_level(logging.DEBUG)
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request = _http_request(agent, context, authority, params=params, operation="write")
    outcome = await runtime.execute_connector_effect(request, params=params, context=context)
    assert outcome.success is True or outcome.success is False
    assert SYNTH_BODY not in caplog.text
    ledger = tmp_path / "state" / "approvals.jsonl"
    if ledger.exists():
        assert SYNTH_BODY not in ledger.read_text(encoding="utf-8")


def _assert_no_mutated_fields(seen: dict[str, Any]) -> None:
    assert seen.get("q") != "MUTATED_AFTER_CONSENT"
    assert seen.get("q") != "MUTATED_AFTER_CLAIM"
    nested = seen.get("nested")
    if type(nested) is dict:
        assert nested.get("value") != "STOLEN"
    assert "exfil" not in seen


def _bind_connector_network_consent(agent: Any, monkeypatch: pytest.MonkeyPatch) -> Any:
    from tests.test_b2c_non_model_egress import FakeNetworkBroker

    broker = FakeNetworkBroker()
    agent._egress_consent_broker = broker
    monkeypatch.setattr(
        "js.security.egress.channel_has_network_egress_adapter",
        lambda _channel: True,
    )
    return broker


@pytest.mark.asyncio
async def test_read_post_consent_nested_mutation_does_not_reach_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    _bind_connector_network_consent(agent, monkeypatch)
    params = {
        "q": "APPROVED",
        "nested": {"value": "SAFE"},
        "url": "https://api.example.test/search",
    }
    request = _http_request(agent, context, authority, params=params, operation="read")
    original = _require(_egress_mod(), "authorize_network_egress")

    async def mutate_after_consent(*args: Any, **kwargs: Any) -> Any:
        auth = await original(*args, **kwargs)
        payload = kwargs.get("payload")
        if type(payload) is dict:
            nested = payload.get("nested")
            if type(nested) is dict:
                nested["value"] = "STOLEN"
            payload["q"] = "MUTATED_AFTER_CONSENT"
            payload["exfil"] = "stolen"
        return auth

    monkeypatch.setattr("js.security.egress.authorize_network_egress", mutate_after_consent)
    handler_calls = 0
    http_calls = 0
    try:
        await runtime.execute_connector_effect(request, params=params, context=context)
    except (PermissionError, ValueError, TypeError):
        pass
    handler_calls = spy.read_calls
    http_calls = effects.http
    for seen in spy.seen_params:
        _assert_no_mutated_fields(seen)
    if handler_calls == 0:
        assert http_calls == 0
        assert spy.seen_params == []
    else:
        assert handler_calls == 1
        assert http_calls == 1
        assert spy.seen_params[0]["q"] == "APPROVED"
        assert spy.seen_params[0]["nested"]["value"] == "SAFE"
        assert "exfil" not in spy.seen_params[0]


@pytest.mark.asyncio
async def test_write_post_claim_nested_mutation_does_not_reach_handler(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from js.security.approvals import ApprovalQueue

    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {
        "q": "APPROVED",
        "nested": {"value": "SAFE"},
        "url": "https://api.example.test/write",
    }
    request = _http_request(agent, context, authority, params=params, operation="write")
    original_hash = agent.approvals.arguments_hash(
        {
            "authority_binding_hash": request.authority_binding_hash(),
            "scope": "publish",
            **_network_fields(params),
        }
    )
    held: dict[str, Any] = {}
    original_snapshot = ApprovalQueue.snapshot_arguments

    def capturing_snapshot(cls: Any, value: Any) -> dict[str, Any]:
        snap = original_snapshot(value)
        if (
            "params" not in held
            and type(snap) is dict
            and "url" in snap
            and "nested" in snap
        ):
            held["params"] = snap
        return snap

    monkeypatch.setattr(ApprovalQueue, "snapshot_arguments", classmethod(capturing_snapshot))
    original_consume = agent.approvals.consume_approved_binding

    def consume_then_mutate(*args: Any, **kwargs: Any) -> Any:
        proof = original_consume(*args, **kwargs)
        live = held.get("params")
        if type(live) is dict:
            nested = live.get("nested")
            if type(nested) is dict:
                nested["value"] = "STOLEN"
            live["q"] = "MUTATED_AFTER_CLAIM"
            live["exfil"] = "stolen"
        return proof

    agent.approvals.consume_approved_binding = consume_then_mutate  # type: ignore[method-assign]
    try:
        await runtime.execute_connector_effect(request, params=params, context=context)
    except (PermissionError, ValueError, TypeError):
        pass
    assert kwargs_hash_unchanged(agent, request, original_hash)
    for seen in spy.seen_params:
        _assert_no_mutated_fields(seen)
    if spy.write_calls == 0:
        assert effects.http == 0
    else:
        assert spy.write_calls == 1
        assert spy.seen_params[0]["q"] == "APPROVED"
        assert spy.seen_params[0]["nested"]["value"] == "SAFE"


def kwargs_hash_unchanged(agent: Any, request: ConnectorExecutionRequestV1, original: str) -> bool:
    current = agent.approvals.arguments_hash(
        {
            "authority_binding_hash": request.authority_binding_hash(),
            "scope": "publish",
            **_network_fields(
                {
                    "q": "APPROVED",
                    "nested": {"value": "SAFE"},
                    "url": "https://api.example.test/write",
                }
            ),
        }
    )
    assert current == original
    return True


@pytest.mark.asyncio
async def test_write_issues_one_network_egress_permit_on_same_card(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request_calls: list[str] = []
    original_request = agent.approvals.request_decision

    def counting_request(tool_name: str, *args: Any, **kwargs: Any) -> Any:
        request_calls.append(tool_name)
        return original_request(tool_name, *args, **kwargs)

    agent.approvals.request_decision = counting_request  # type: ignore[method-assign]
    request = _http_request(agent, context, authority, params=params, operation="write")
    claim_count = 0
    original_consume = agent.approvals.consume_approved_binding

    def counting_consume(*args: Any, **kwargs: Any) -> Any:
        nonlocal claim_count
        proof = original_consume(*args, **kwargs)
        claim_count += 1
        return proof

    agent.approvals.consume_approved_binding = counting_consume  # type: ignore[method-assign]
    issuer = agent._network_permit_issuer
    issued: list[Any] = []
    consumed: list[Any] = []
    original_issue = issuer.issue
    original_verify = issuer.verify_and_consume

    def counting_issue(**kwargs: Any) -> Any:
        permit = original_issue(**kwargs)
        issued.append(permit)
        return permit

    def counting_verify(permit: Any, **kwargs: Any) -> None:
        consumed.append(permit)
        original_verify(permit, **kwargs)

    monkeypatch.setattr(issuer, "issue", counting_issue)
    monkeypatch.setattr(issuer, "verify_and_consume", counting_verify)
    outcome = await runtime.execute_connector_effect(request, params=params, context=context)
    assert outcome.success is True
    assert request_calls.count("connector.http_spy.write") == 1
    assert request_calls.count("connector_egress") == 0
    assert claim_count == 1
    assert len(issued) == 1
    assert len(consumed) == 1
    permit = issued[0]
    assert permit.kind == "connector_egress"
    assert type(permit.attempt_id) is str and len(permit.attempt_id) == 32
    assert permit.payload_digest
    assert permit.endpoint_generation
    assert getattr(permit, "effect_id", "")
    assert getattr(permit, "arguments_hash", "")
    assert getattr(permit, "consent_receipt_hash", "")
    assert spy.write_calls == 1
    from js.security.egress import digest_jsonable

    assert digest_jsonable(spy.seen_params[0]) == permit.payload_digest


@pytest.mark.asyncio
async def test_write_forged_permit_mac_handler_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dataclasses import replace

    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request = _http_request(agent, context, authority, params=params, operation="write")
    issuer = agent._network_permit_issuer
    original_issue = issuer.issue

    def forged_mac(**kwargs: Any) -> Any:
        permit = original_issue(**kwargs)
        return replace(permit, mac="0" * 64)

    monkeypatch.setattr(issuer, "issue", forged_mac)
    with pytest.raises((PermissionError, ValueError, TypeError)):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert spy.write_calls == 0
    assert effects.http == 0


@pytest.mark.asyncio
async def test_write_permit_replay_second_handler_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    first = _http_request(agent, context, authority, params=params, operation="write")
    issuer = agent._network_permit_issuer
    saved: dict[str, Any] = {}
    original_issue = issuer.issue

    def reuse_or_issue(**kwargs: Any) -> Any:
        if "permit" in saved:
            return saved["permit"]
        permit = original_issue(**kwargs)
        saved["permit"] = permit
        return permit

    monkeypatch.setattr(issuer, "issue", reuse_or_issue)
    outcome = await runtime.execute_connector_effect(first, params=params, context=context)
    first_handler = spy.write_calls
    second = _http_request(agent, context, authority, params=params, operation="write")
    try:
        await runtime.execute_connector_effect(second, params=params, context=context)
    except (PermissionError, ValueError, TypeError):
        pass
    assert spy.write_calls == first_handler
    if first_handler == 1:
        assert outcome.success is True
    assert spy.write_calls <= 1


@pytest.mark.asyncio
async def test_write_permit_effect_id_or_arguments_hash_swap_handler_zero(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from dataclasses import replace

    agent, runtime, context, authority, *_rest = _runtime_bundle(tmp_path)
    effects = SideEffects()
    spy = HttpSpyConnector(effects)
    _install_spy(runtime, spy)
    params = {"body": SYNTH_BODY, "url": "https://api.example.test/write"}
    request = _http_request(agent, context, authority, params=params, operation="write")
    issuer = agent._network_permit_issuer
    original_issue = issuer.issue

    def swap_fields(**kwargs: Any) -> Any:
        permit = original_issue(**kwargs)
        if hasattr(permit, "effect_id"):
            permit = replace(permit, effect_id="forged-effect-id")
        if hasattr(permit, "arguments_hash"):
            permit = replace(permit, arguments_hash="f" * 64)
        return permit

    monkeypatch.setattr(issuer, "issue", swap_fields)
    with pytest.raises((PermissionError, ValueError, TypeError, AttributeError)):
        await runtime.execute_connector_effect(request, params=params, context=context)
    assert spy.write_calls == 0
    assert effects.http == 0


def _connector_permit_base(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "kind": "connector_egress",
        "attempt_id": "a" * 32,
        "attempt_hash": "b" * 64,
        "owner_key_hash": "owner-a",
        "session_id": "session-a",
        "run_id": "run-a",
        "channel": "test",
        "product_id": "js-agent",
        "endpoint_generation": "e" * 64,
        "credential_generation": "none",
        "payload_digest": "p" * 64,
        "provenance_digest": "q" * 64,
        "consent_receipt_hash": "sha256:" + "c" * 64,
        "appshell_epoch": "1",
        "effect_id": "connector:lease-a:write",
        "arguments_hash": "d" * 64,
        "endpoint_digest": "f" * 64,
    }
    base.update(overrides)
    return base


def test_write_permit_mac_covers_effect_id() -> None:
    from dataclasses import replace

    from js.models.permit import NetworkEgressPermitError, NetworkEgressPermitIssuer

    issuer = NetworkEgressPermitIssuer(key=b"k" * 32)
    base = _connector_permit_base()
    permit = issuer.issue(**base)
    tampered = replace(permit, effect_id="forged-effect-id")
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(tampered, **{**base, "effect_id": "forged-effect-id"})


def test_write_permit_mac_covers_arguments_hash_and_payload_digest() -> None:
    from dataclasses import replace

    from js.models.permit import NetworkEgressPermitError, NetworkEgressPermitIssuer

    issuer = NetworkEgressPermitIssuer(key=b"k" * 32)
    base = _connector_permit_base()
    permit = issuer.issue(**base)
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(
            replace(permit, arguments_hash="0" * 64),
            **{**base, "arguments_hash": "0" * 64},
        )
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(
            replace(permit, payload_digest="0" * 64),
            **{**base, "payload_digest": "0" * 64},
        )


def test_write_permit_replay_same_binding_second_consume_zero() -> None:
    from js.models.permit import NetworkEgressPermitError, NetworkEgressPermitIssuer

    issuer = NetworkEgressPermitIssuer(key=b"k" * 32)
    base = _connector_permit_base()
    permit = issuer.issue(**base)
    issuer.verify_and_consume(permit, **base)
    with pytest.raises(NetworkEgressPermitError):
        issuer.verify_and_consume(permit, **base)
