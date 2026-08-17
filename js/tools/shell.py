"""Sandboxed shell execution tool."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from js.config import ToolLimits
from js.security.guard import BehaviorGuard, SecurityDecisionType
from js.security.sandbox import SandboxExecutor
from js.tools.registry import ToolParam, ToolResult, ToolSpec

# ---------------------------------------------------------------------------
# Argument-level deny rules (F-09)
#
# Being on the executable allowlist is not enough: several retained commands
# carry documented argument-level execution/file-access bypasses.  Each rule
# below receives the full argv (including argv[0]) and returns a denial reason
# or None.  Rules are fail-closed: an unparseable or ambiguous shape is denied.
# ---------------------------------------------------------------------------

_FIND_DENIED_FLAGS = frozenset({
    "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprintf",
})

_AWK_DENIED_PROGRAM_PATTERNS = (
    (re.compile(r"\bsystem\s*\("), "awk system() call"),
    (re.compile(r"\bgetline\b"), "awk getline file/pipe read"),
    (re.compile(r"(?:print|printf)[^'\";]*(?:>>|>|<[^=]|\|\s*\")"), "awk output redirection/pipe"),
)

_GIT_DENIED_SUBCOMMANDS = frozenset({"config", "alias"})
_GIT_DENIED_LONG_FLAGS = (
    "--config-env",
    "--exec-path",
)
_GIT_DENIED_SUBSTRINGS = ("ext::", "upload-pack")

# sed `e` (execute) / `w` (write file) commands, allowing address prefixes
# like `1e id`, `$w out`, `/re/e cmd` and command separators.
_SED_DENIED_COMMAND_RE = re.compile(r"(?:^|[;{}\s0-9,$/])[ew](?:[;}\s]|$)")

_TAR_DENIED_LONG_FLAGS = (
    "--directory",
    "--to-command",
    "--checkpoint-action",
    "--use-compress-program",
    "--rsh-command",
    "--absolute-names",
)
# Short tar option letters that change directory, keep absolute names, or run
# external commands (C/P take effect per-member; bundled forms like -xfC).
_TAR_DENIED_SHORT_LETTERS = frozenset("CP")
# Short tar options that consume the following argv token as a value.
_TAR_VALUE_SHORT_LETTERS = frozenset("fCb")

_JQ_DENIED_FLAGS = frozenset({
    "--arg-file",
    "--slurpfile",
    "--rawfile",
    "-f",
    "--from-file",
})

# ripgrep preprocessor / helper-binary execution vectors (F-09).
_RG_DENIED_FLAGS = frozenset({
    "--pre",
    "--pre-path",
    "--hostname-bin",
})


def _find_arg_error(args: list[str]) -> str | None:
    for token in args[1:]:
        if token in _FIND_DENIED_FLAGS or token.startswith("-fprint"):
            return f"find argument denied (execution/file-write vector): {token}"
    return None


def _awk_arg_error(args: list[str]) -> str | None:
    idx = 1
    while idx < len(args):
        token = args[idx]
        if token in ("-f", "--file") or token.startswith("--file="):
            return f"awk program file denied (unscanned code): {token}"
        # Options with separate values (-F, -v) carry no program text.
        if token in ("-F", "-v"):
            idx += 2
            continue
        if token.startswith("-"):
            idx += 1
            continue
        for pattern, reason in _AWK_DENIED_PROGRAM_PATTERNS:
            if pattern.search(token):
                return f"awk program denied ({reason})"
        idx += 1
    return None


def _git_arg_error(args: list[str]) -> str | None:
    subcommand: str | None = None
    for token in args[1:]:
        if token == "-c" or token.startswith("-c"):
            return f"git inline config denied (alias/pager RCE vector): {token}"
        for flag in _GIT_DENIED_LONG_FLAGS:
            if token == flag or token.startswith(flag + "="):
                return f"git flag denied (config injection vector): {token}"
        for needle in _GIT_DENIED_SUBSTRINGS:
            if needle in token:
                return f"git argument denied ({needle} execution vector): {token}"
        if subcommand is None and not token.startswith("-"):
            subcommand = token
    if subcommand in _GIT_DENIED_SUBCOMMANDS:
        return f"git subcommand denied (config/alias manipulation): {subcommand}"
    return None


def _sed_arg_error(args: list[str]) -> str | None:
    for token in args[1:]:
        if token == "--in-place" or token.startswith("--in-place="):
            return f"sed in-place edit denied (file overwrite vector): {token}"
        if token.startswith("-i") and not token.startswith("--"):
            return f"sed in-place edit denied (file overwrite vector): {token}"
    for token in args[1:]:
        if token.startswith("-"):
            continue
        if _SED_DENIED_COMMAND_RE.search(token):
            return "sed script denied (e/w command execution/write vector)"
    return None


def _workspace_path_error(
    token: str, *, cwd: Path, workspace: Path, label: str
) -> str | None:
    target = Path(token)
    candidate = target if target.is_absolute() else cwd / target
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return f"{label} denied (unresolvable path)"
    try:
        resolved.relative_to(workspace)
    except ValueError:
        return f"{label} denied (outside workspace): {token}"
    return None


def _looks_like_fs_path(token: str) -> bool:
    if not token or token in {".", "-"}:
        return False
    if token.startswith("/") or token.startswith("~"):
        return True
    return ".." in token.split("/")


def _generic_path_arg_error(args: list[str], *, cwd: Path, workspace: Path) -> str | None:
    for token in args[1:]:
        if token.startswith("-") or not _looks_like_fs_path(token):
            continue
        error = _workspace_path_error(
            token, cwd=cwd, workspace=workspace, label="command path"
        )
        if error is not None:
            return error
    return None


def _sort_arg_error(args: list[str], *, cwd: Path, workspace: Path) -> str | None:
    idx = 1
    while idx < len(args):
        token = args[idx]
        output: str | None = None
        if token in ("-o", "--output"):
            if idx + 1 >= len(args):
                return "sort output denied (missing path)"
            output = args[idx + 1]
            idx += 2
        elif token.startswith("--output="):
            output = token.split("=", 1)[1]
            idx += 1
        elif token.startswith("-o") and not token.startswith("--") and token != "-o":
            output = token[2:]
            idx += 1
        else:
            idx += 1
            continue
        error = _workspace_path_error(
            output, cwd=cwd, workspace=workspace, label="sort output"
        )
        if error is not None:
            return error
    return None


def _tar_arg_error(args: list[str], *, cwd: Path, workspace: Path) -> str | None:
    idx = 1
    while idx < len(args):
        token = args[idx]
        if token.startswith("--"):
            name = token.split("=", 1)[0]
            if name in _TAR_DENIED_LONG_FLAGS:
                return f"tar flag denied (directory-escape/exec vector): {token}"
            if name == "--file":
                if "=" in token:
                    archive = token.split("=", 1)[1]
                elif idx + 1 < len(args):
                    archive = args[idx + 1]
                    idx += 1
                else:
                    return "tar archive denied (missing --file value)"
                error = _workspace_path_error(
                    archive, cwd=cwd, workspace=workspace, label="tar archive"
                )
                if error is not None:
                    return error
        elif token.startswith("-") and len(token) > 1:
            letters = token[1:]
            denied = _TAR_DENIED_SHORT_LETTERS.intersection(letters)
            if denied:
                return f"tar flag denied (directory-escape/absolute-path vector): -{sorted(denied)[0]}"
            value_letters = [c for c in letters if c in _TAR_VALUE_SHORT_LETTERS]
            if value_letters and letters.endswith(value_letters[-1]):
                if idx + 1 >= len(args):
                    return "tar archive denied (missing option value)"
                if "f" in value_letters:
                    error = _workspace_path_error(
                        args[idx + 1], cwd=cwd, workspace=workspace, label="tar archive"
                    )
                    if error is not None:
                        return error
                idx += 1  # skip the option value (e.g. archive after -czf)
        else:
            # Archive member: reject traversal and absolute paths.
            if token.startswith("/"):
                return f"tar member denied (absolute path): {token}"
            if ".." in token.split("/"):
                return f"tar member denied (path traversal): {token}"
        idx += 1
    return None


def _mv_arg_error(args: list[str], *, cwd: Path, workspace: Path) -> str | None:
    positional = [t for t in args[1:] if not t.startswith("-")]
    if len(positional) < 2:
        return None
    target = Path(positional[-1])
    candidate = target if target.is_absolute() else cwd / target
    try:
        resolved = candidate.resolve(strict=False)
    except (OSError, RuntimeError):
        return "mv target denied (unresolvable path)"
    try:
        resolved.relative_to(workspace)
    except ValueError:
        return f"mv target denied (outside workspace): {positional[-1]}"
    # Fail-closed: never let mv silently overwrite an existing non-directory.
    if resolved.exists() and not resolved.is_dir():
        return f"mv target denied (would overwrite existing file): {positional[-1]}"
    return None


def _jq_arg_error(args: list[str]) -> str | None:
    for token in args[1:]:
        if token in _JQ_DENIED_FLAGS:
            return f"jq flag denied (arbitrary file read vector): {token}"
        for flag in _JQ_DENIED_FLAGS:
            if flag.startswith("--") and token.startswith(flag + "="):
                return f"jq flag denied (arbitrary file read vector): {token}"
    return None


def _rg_arg_error(args: list[str]) -> str | None:
    for token in args[1:]:
        if token in _RG_DENIED_FLAGS:
            return f"rg flag denied (preprocessor/exec vector): {token}"
        for flag in _RG_DENIED_FLAGS:
            if token.startswith(flag + "="):
                return f"rg flag denied (preprocessor/exec vector): {token}"
    return None


_STATIC_ARG_RULES = {
    "find": _find_arg_error,
    "awk": _awk_arg_error,
    "git": _git_arg_error,
    "sed": _sed_arg_error,
    "jq": _jq_arg_error,
    "rg": _rg_arg_error,
}

_PATHFUL_ARG_RULES = {
    "mv": _mv_arg_error,
    "tar": _tar_arg_error,
    "sort": _sort_arg_error,
}


class ShellTool:
    """Secure shell command execution."""

    def __init__(self, workspace: Path, limits: ToolLimits, guard: BehaviorGuard) -> None:
        self.workspace = workspace.resolve()
        self.limits = limits
        self.guard = guard
        self.executor = SandboxExecutor(
            workspace=workspace,
            timeout=limits.shell_timeout,
            max_output_bytes=limits.shell_max_output_bytes,
            strict_isolation=True,
        )

    def get_spec(self) -> ToolSpec:
        return ToolSpec(
            name="shell",
            description="Execute a shell command. Use with caution. Commands run in workspace.",
            parameters=[
                ToolParam("command", "string", "Shell command to execute"),
                ToolParam("cwd", "string", "Working directory (relative to workspace)", required=False),
                ToolParam("timeout", "integer", "Override timeout in seconds", required=False),
            ],
            dangerous=True,
        )

    async def execute(
        self, command: str, cwd: str = ".", timeout: int = 0
    ) -> ToolResult:
        resolved_cwd, cwd_error = self.executor.resolve_cwd(cwd)
        if cwd_error is not None or resolved_cwd is None:
            return ToolResult(success=False, error=cwd_error or "Sandbox cwd denied")

        allowlist_error = self._command_allowlist_error(command, cwd=resolved_cwd)
        if allowlist_error is not None:
            return ToolResult(success=False, error=allowlist_error)

        # Security check
        decision = self.guard.check_command(command, cwd)
        if decision.decision == SecurityDecisionType.BLOCK:
            return ToolResult(success=False, error=f"Security: {decision.reason}")
        elif decision.decision == SecurityDecisionType.WARN:
            # Still allow but mark
            pass

        path_decision = self.guard.check_path_operation(
            str(resolved_cwd), "read"
        )
        if path_decision.decision == SecurityDecisionType.BLOCK:
            return ToolResult(success=False, error=path_decision.reason)

        result = await self.executor.execute(
            command,
            cwd=str(resolved_cwd),
            timeout=timeout or self.limits.shell_timeout,
            network_allowed=False,
            fs_restricted=True,
        )

        output = result.stdout
        if result.stderr:
            output += f"\n[stderr]\n{result.stderr}"

        if result.killed:
            output += "\n[Process was terminated (timeout or resource limit)]"

        return ToolResult(
            success=result.returncode == 0 and not result.killed,
            output=output,
            error=result.stderr if result.returncode != 0 else "",
            metadata={
                "returncode": result.returncode,
                "duration_ms": result.duration_ms,
                "killed": result.killed,
            },
        )

    def _command_allowlist_error(
        self, command: str, cwd: Path | None = None
    ) -> str | None:
        """Require approved bare names plus per-command argument safety.

        Fail-closed on every layer: unparseable command, unlisted executable,
        or a dangerous argument pattern all deny before any process spawns.
        """

        try:
            from js.security.parser import extract_all_args, has_subshell, parse

            parsed = parse(command)
            if parsed is None:
                return "Shell command allowlist denied an unparseable command"
            if has_subshell(parsed):
                return (
                    "Shell command allowlist denied a subshell/process substitution"
                )
            command_args = extract_all_args(parsed)
        except Exception:
            return "Shell command allowlist denied an unparseable command"
        if not command_args:
            return "Shell command allowlist denied an empty command"
        allowed = set(self.limits.shell_command_allowlist)
        effective_cwd = (cwd or self.workspace).resolve()
        for args in command_args:
            if not args:
                return "Shell command allowlist denied an empty command"
            raw_name = args[0]
            if "/" in raw_name or "\\" in raw_name or raw_name not in allowed:
                return f"Shell command allowlist denied executable: {raw_name}"
            pathful = _PATHFUL_ARG_RULES.get(raw_name)
            if pathful is not None:
                arg_error = pathful(args, cwd=effective_cwd, workspace=self.workspace)
                if arg_error is not None:
                    return f"Shell command allowlist denied: {arg_error}"
            else:
                rule = _STATIC_ARG_RULES.get(raw_name)
                if rule is not None:
                    arg_error = rule(args)
                    if arg_error is not None:
                        return f"Shell command allowlist denied: {arg_error}"
            path_error = _generic_path_arg_error(
                args, cwd=effective_cwd, workspace=self.workspace
            )
            if path_error is not None:
                return f"Shell command allowlist denied: {path_error}"
        return None

    def register(self, registry: Any) -> None:
        registry.register(self.get_spec(), self.execute)
