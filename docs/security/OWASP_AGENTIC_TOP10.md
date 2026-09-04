# OWASP Agentic Top 10 mapping (Orin 2.0)

Architectural mitigations only. Prompt injection is not claimed solved.

| ID | Title | Mechanism in this tree | Tests |
| --- | --- | --- | --- |
| ASI01 | Agent Goal Hijack | plan-commit BIND + taint narrowing + ExecKernel slot check | `tests/orin_guard/test_kernel.py` |
| ASI02 | Tool Misuse | single-use leases + GateKernel consume | `js/echo/capability.py`, gate tests |
| ASI03 | Identity Impersonation | `resolve_allowlist_identity` immutable IDs only | identity tests, Telegram adapter |
| ASI04 | Supply Chain (skills/MCP) | MCPGate content-hash pin, community never auto-promote | MCP + forge tests |
| ASI05 | Unexpected Code Execution | `reject_lexical_bypass` + OS sandbox fail-closed | exec_parse + os_sandbox tests |
| ASI06 | Memory Poisoning | ExperienceBank taint gate; constitution paths not evolvable | phylogeny + experience tests |
| ASI07 | Insecure Inter-Agent | peer uid+pid auth; loopback is not identity | peer tests, orind `_check_peer` |
| ASI08 | Excessive Agency | lethal trifecta conjunction hard deny | conjunction tests |
| ASI09 | Credential Leakage | CredBroker opaque tokens; no raw keys in sandbox | cred tests |
| ASI10 | Misaligned Evolution | tighten/note auto; widen never unattended; eval gate no off switch | phylogeny + eval_gate tests |
