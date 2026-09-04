"""Process-group RSS accounting helpers."""

from __future__ import annotations

import os

from js.echo.os_sandbox import SandboxExecutor


def test_process_group_rss_covers_current_process() -> None:
    rss = SandboxExecutor._process_group_rss(os.getpid())
    assert rss > 0
    tree = SandboxExecutor._process_tree_rss(os.getpid())
    assert rss >= tree


def test_accounted_rss_prefers_larger_of_group_and_cgroup(monkeypatch) -> None:
    executor = SandboxExecutor.__new__(SandboxExecutor)
    monkeypatch.setattr(SandboxExecutor, "_process_group_rss", staticmethod(lambda _pid: 100))
    # Modest cgroup overshoot still wins (dedicated sandbox cgroup).
    monkeypatch.setattr(SandboxExecutor, "_cgroup_rss", staticmethod(lambda _pid: 250))
    assert executor._accounted_rss(1) == 250
    monkeypatch.setattr(SandboxExecutor, "_cgroup_rss", staticmethod(lambda _pid: None))
    assert executor._accounted_rss(1) == 100
    monkeypatch.setattr(SandboxExecutor, "_cgroup_rss", staticmethod(lambda _pid: 50))
    assert executor._accounted_rss(1) == 100


def test_accounted_rss_ignores_shared_parent_cgroup(monkeypatch) -> None:
    """CI containers report the whole pod in memory.current — do not OOM on that."""
    executor = SandboxExecutor.__new__(SandboxExecutor)
    monkeypatch.setattr(
        SandboxExecutor, "_process_group_rss", staticmethod(lambda _pid: 26_000_000)
    )
    monkeypatch.setattr(
        SandboxExecutor, "_cgroup_rss", staticmethod(lambda _pid: 1_700_000_000)
    )
    assert executor._accounted_rss(1) == 26_000_000


def test_cgroup_rss_is_none_or_non_negative() -> None:
    value = SandboxExecutor._cgroup_rss(os.getpid())
    if value is not None:
        assert value >= 0


def test_bwrap_placeholder_for_missing_git(tmp_path, monkeypatch) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    executor = SandboxExecutor(workspace, strict_isolation=False)
    monkeypatch.setattr(executor, "_has_bwrap", True)
    monkeypatch.setattr("echo_core.os_sandbox.platform.system", lambda: "Linux")
    wrapped = executor._wrap_filesystem_isolation(
        ["echo", "ok"],
        fs_restricted=True,
        network_allowed=False,
    )
    # Host-side mkdir (not bwrap --dir) so the post-exec planted-.git check
    # does not treat our deny mount point as attacker metadata.
    git_dir_args = [
        wrapped[i + 1]
        for i, part in enumerate(wrapped)
        if part == "--dir" and i + 1 < len(wrapped)
    ]
    assert str(workspace / ".git") not in git_dir_args
    assert not any(arg.endswith("/.git") or arg.endswith("\\.git") for arg in git_dir_args)
    assert (workspace / ".git").is_dir()
    assert str(workspace / ".git") in wrapped
    git_binds = [
        i
        for i, part in enumerate(wrapped)
        if part == "--ro-bind"
        and i + 2 < len(wrapped)
        and wrapped[i + 2] == str(workspace / ".git")
    ]
    assert git_binds
