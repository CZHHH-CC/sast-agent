"""Thin wrappers around `git` and `gh` CLIs.

All functions are **blocking subprocess** calls. Kept separate from the LLM
code so tests can monkeypatch or replace easily.

Never invoke `gh` without explicit user intent — it can push commits and
open PRs. Callers (the `fix` CLI command) guard this with flags.
"""

from __future__ import annotations

import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path


class GitError(RuntimeError):
    pass


class GhError(RuntimeError):
    pass


@dataclass
class PrCreateResult:
    url: str
    number: int | None


def git(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        capture_output=True, text=True, check=check,
    )


def gh(repo: Path, *args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["gh", *args],
        cwd=str(repo),
        capture_output=True, text=True, check=check,
    )


# ---------- git operations ----------

def current_branch(repo: Path) -> str:
    return git(repo, "rev-parse", "--abbrev-ref", "HEAD").stdout.strip()


def head_sha(repo: Path, short: bool = False) -> str:
    cmd = ("rev-parse", "--short", "HEAD") if short else ("rev-parse", "HEAD")
    return git(repo, *cmd).stdout.strip()


def create_branch(repo: Path, branch: str, from_ref: str | None = None) -> None:
    args = ["checkout", "-b", branch]
    if from_ref:
        args.append(from_ref)
    p = git(repo, *args, check=False)
    if p.returncode != 0:
        raise GitError(f"create_branch({branch}) failed: {p.stderr.strip()}")


def checkout(repo: Path, ref: str) -> None:
    p = git(repo, "checkout", ref, check=False)
    if p.returncode != 0:
        raise GitError(f"checkout({ref}) failed: {p.stderr.strip()}")


def apply_patch(repo: Path, diff_text: str) -> None:
    """Apply a unified diff to the working tree. Raises GitError on failure."""
    if not diff_text.strip():
        raise GitError("empty patch")
    # Write diff to a temp file so git's own parser handles line endings.
    with tempfile.NamedTemporaryFile(
        "w", suffix=".patch", delete=False, encoding="utf-8"
    ) as f:
        f.write(diff_text if diff_text.endswith("\n") else diff_text + "\n")
        patch_path = f.name
    try:
        p = git(
            repo, "apply", "--whitespace=nowarn", patch_path, check=False,
        )
        if p.returncode != 0:
            # retry with 3-way in case of context drift
            p2 = git(repo, "apply", "--3way", patch_path, check=False)
            if p2.returncode != 0:
                raise GitError(
                    f"git apply failed.\n-- stderr --\n{p.stderr}\n-- 3way stderr --\n{p2.stderr}"
                )
    finally:
        Path(patch_path).unlink(missing_ok=True)


def commit_all(repo: Path, message: str) -> str:
    """Stage all changes + commit. Returns commit sha. Raises if no changes."""
    git(repo, "add", "-A")
    p = git(repo, "commit", "-m", message, check=False)
    if p.returncode != 0:
        raise GitError(f"commit failed: {p.stderr.strip() or p.stdout.strip()}")
    return head_sha(repo, short=True)


def push(repo: Path, branch: str, remote: str = "origin", set_upstream: bool = True) -> None:
    args = ["push"]
    if set_upstream:
        args += ["-u", remote, branch]
    else:
        args += [remote, branch]
    p = git(repo, *args, check=False)
    if p.returncode != 0:
        raise GitError(f"push({branch}) failed: {p.stderr.strip()}")


# ---------- gh operations ----------

def pr_comment(repo: Path, pr_number: int, body_file: Path) -> None:
    p = gh(repo, "pr", "comment", str(pr_number), "--body-file", str(body_file), check=False)
    if p.returncode != 0:
        raise GhError(f"gh pr comment failed: {p.stderr.strip()}")


def pr_create(
    repo: Path, *, base: str, head: str, title: str, body_file: Path,
) -> PrCreateResult:
    p = gh(
        repo, "pr", "create",
        "--base", base, "--head", head,
        "--title", title, "--body-file", str(body_file),
        check=False,
    )
    if p.returncode != 0:
        raise GhError(f"gh pr create failed: {p.stderr.strip()}")
    url = p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
    num: int | None = None
    if url and "/pull/" in url:
        try:
            num = int(url.rsplit("/", 1)[-1])
        except ValueError:
            pass
    return PrCreateResult(url=url, number=num)


def issue_create(repo: Path, *, title: str, body_file: Path, label: str | None = None) -> str:
    args = ["issue", "create", "--title", title, "--body-file", str(body_file)]
    if label:
        args += ["--label", label]
    p = gh(repo, *args, check=False)
    if p.returncode != 0:
        raise GhError(f"gh issue create failed: {p.stderr.strip()}")
    return p.stdout.strip().splitlines()[-1] if p.stdout.strip() else ""
