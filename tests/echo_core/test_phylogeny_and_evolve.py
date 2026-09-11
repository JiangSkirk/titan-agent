"""echo-core phylogeny, experience, and evolution polarity tests."""

from __future__ import annotations

from pathlib import Path

import pytest
from echo_core.evolve.code_gate import CodeEvolutionDenied, assert_code_gate_open
from echo_core.evolve.curator import Curator
from echo_core.evolve.eval_gate import EvalGateDenied, eval_gate
from echo_core.evolve.forge import ForgeDenied, SkillForge
from echo_core.evolve.prompt import PromptCandidate, assert_volatile_only, pareto_select
from echo_core.evolve.reflex import ReflexStaging
from echo_core.memory.experience import ExperienceBank, ebbinghaus_retention, six_signal_score
from echo_core.memory.frozen import FrozenMemory, FrozenMemoryFull
from echo_core.phylogeny import (
    POLARITY_NOTE,
    POLARITY_TIGHTEN,
    POLARITY_WIDEN,
    Phylogeny,
    PhylogenyError,
)
from echo_core.spi.guardian import GuardianDenied, NullGuardian
from echo_core.taint import USER_TURN, WEB_CONTENT


def test_null_guardian_fail_closed() -> None:
    g = NullGuardian()
    with pytest.raises(GuardianDenied):
        g.stamp(owner="o", session="s", run="r", effect_class="tool", grants=frozenset(), budget=1)


def test_tighten_auto_commits(tmp_path: Path) -> None:
    phy = Phylogeny(tmp_path)
    node = phy.propose(
        "owner", POLARITY_TIGHTEN, "stricter deny", {"kind": "tighten"}, taint=USER_TURN
    )
    assert node.status == "committed"


def test_note_rejects_web_taint(tmp_path: Path) -> None:
    phy = Phylogeny(tmp_path)
    with pytest.raises(PhylogenyError, match="USER_TURN"):
        phy.propose("owner", POLARITY_NOTE, "pref", {"kind": "note"}, taint=WEB_CONTENT)
    with pytest.raises(PhylogenyError, match="USER_TURN"):
        phy.propose("owner", POLARITY_NOTE, "pref", {"kind": "note"}, taint=0)


def test_widen_never_auto_commits(tmp_path: Path) -> None:
    phy = Phylogeny(tmp_path)
    node = phy.propose("owner", POLARITY_WIDEN, "new skill", {"kind": "skill"}, taint=USER_TURN)
    assert node.status == "proposed"
    assert phy.heads("owner") == []
    bound = phy.bind_widen(node.node_id, "owner", decided_by="owner")
    assert bound.status == "bound"
    assert phy.heads("owner") == [("new skill", "widen")]


def test_widen_untrusted_taint_rejected(tmp_path: Path) -> None:
    phy = Phylogeny(tmp_path)
    with pytest.raises(PhylogenyError, match="untrusted"):
        phy.propose("owner", POLARITY_WIDEN, "bad", {"kind": "skill"}, taint=WEB_CONTENT)


def test_constitution_paths_not_evolvable(tmp_path: Path) -> None:
    phy = Phylogeny(tmp_path)
    with pytest.raises(PhylogenyError, match="constitution"):
        phy.propose(
            "owner",
            POLARITY_TIGHTEN,
            "tamper",
            {"path": "echo_core/ledger/journal.py"},
            taint=USER_TURN,
        )


def test_eval_gate_has_no_skip() -> None:
    with pytest.raises(EvalGateDenied, match="cannot be skipped"):
        eval_gate(None, baseline=1.0)
    with pytest.raises(EvalGateDenied, match="below baseline"):
        eval_gate(lambda: 0.1, baseline=1.0)
    assert eval_gate(lambda: 1.0, baseline=1.0) == 1.0


def test_code_gate_default_closed() -> None:
    with pytest.raises(CodeEvolutionDenied):
        assert_code_gate_open(enabled=False)


def test_experience_taint_gate(tmp_path: Path) -> None:
    bank = ExperienceBank(tmp_path)
    signals = {
        "relevance": 1.0,
        "frequency": 1.0,
        "query_diversity": 1.0,
        "recency": 1.0,
        "consolidation": 1.0,
        "conceptual_richness": 1.0,
        "recall_count": 2,
        "unique_queries": 2,
    }
    assert (
        bank.consolidate_deep("o", "web junk", "hint", taint=WEB_CONTENT, signals=signals) is None
    )
    assert bank.consolidate_deep("o", "untagged", "hint", taint=0, signals=signals) is None
    kept = bank.consolidate_deep("o", "trusted pattern", "hint", taint=USER_TURN, signals=signals)
    assert kept is not None
    assert bank.search("o", "trusted")


def test_six_signal_weights() -> None:
    assert six_signal_score(
        relevance=1,
        frequency=1,
        query_diversity=1,
        recency=1,
        consolidation=1,
        conceptual_richness=1,
    ) == pytest.approx(1.0)
    assert ebbinghaus_retention(0, 1.0) == pytest.approx(1.0)
    assert ebbinghaus_retention(1e9, 1.0) < 0.01


def test_frozen_memory_errors_when_full() -> None:
    frozen = FrozenMemory(max_items=1)
    frozen.add("a")
    with pytest.raises(FrozenMemoryFull):
        frozen.add("b")


def test_forge_never_auto_promotes(tmp_path: Path) -> None:
    forge = SkillForge(tmp_path)
    with pytest.raises(ForgeDenied, match="3 related"):
        forge.admit("o", "body", verified_runs=2)
    record = forge.admit("o", "body", verified_runs=3)
    assert record.trust == "community"
    with pytest.raises(ForgeDenied, match="never auto-promote"):
        forge.promote(record.skill_id)


def test_curator_archives_never_deletes(tmp_path: Path) -> None:
    skill = tmp_path / "abc.skill.json"
    skill.write_text("{}", encoding="utf-8")
    curator = Curator(tmp_path)
    dest = curator.archive_skill(skill, actor="owner")
    assert dest.is_file()
    assert skill.is_file()
    assert (tmp_path / "curator.jsonl").is_file()


def test_prompt_pareto_safety_hard_dominates() -> None:
    with pytest.raises(Exception, match="constitution"):
        assert_volatile_only("CONSTITUTION text")
    winner = pareto_select(
        (
            PromptCandidate("a", 0.99, 10.0, safety_events=1),
            PromptCandidate("b", 0.50, 20.0, safety_events=0),
        )
    )
    assert winner.text == "b"


def test_reflex_stays_proposed(tmp_path: Path) -> None:
    item = ReflexStaging(tmp_path).propose("o", "reflex", "candidate")
    assert item.status == "proposed"


def test_rollback_has_no_off_switch(tmp_path: Path) -> None:
    phy = Phylogeny(tmp_path)
    node = phy.propose(
        "owner", POLARITY_TIGHTEN, "stricter deny", {"kind": "tighten"}, taint=USER_TURN
    )
    rolled = phy.rollback(node.node_id, "owner")
    assert rolled.status == "regressed"
    assert phy.heads("owner") == []


def test_flush_bridge_skips_unknown_taint(tmp_path: Path) -> None:
    from js.memory.experience_bridge import flush_before_compress

    assert flush_before_compress(tmp_path, "o", "summary", "hint", taint=0) is None
    assert not (tmp_path / "experience_bank.db").exists()


def test_experience_search_is_owner_scoped(tmp_path: Path) -> None:
    bank = ExperienceBank(tmp_path)
    signals = {
        "relevance": 1.0,
        "frequency": 1.0,
        "query_diversity": 1.0,
        "recency": 1.0,
        "consolidation": 1.0,
        "conceptual_richness": 1.0,
        "recall_count": 2,
        "unique_queries": 2,
    }
    kept = bank.consolidate_deep(
        "alice", "trusted pattern", "hint", taint=USER_TURN, signals=signals
    )
    assert kept is not None
    assert bank.search("alice", "trusted")
    assert bank.search("bob", "trusted") == []
