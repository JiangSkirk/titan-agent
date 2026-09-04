"""Echo ledger package.

Kernel modules are shims to ``echo_core.ledger``. Product release gates
(``release_gates``, ``evidence_export``, ``final_evidence``, ``service``)
remain in this tree and may import Host ``desktop/`` / ``scripts/``.
"""

from __future__ import annotations
