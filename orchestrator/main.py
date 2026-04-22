"""CLI entrypoint for sast-agent (MVP: Scanner + Validator)."""

from __future__ import annotations

import anyio
import functools
import json
import subprocess
import sys
from pathlib import Path

import click
from rich.console import Console
from rich.table import Table

from .baseline import Baseline
from .fingerprint import make_fingerprint
from . import github as gh_ops
from .fixer_pool import fix_all
from .report import render_markdown
from .reviewer_client import coerce_verdict, review_one
from .scanner_client import run_scanner_batched
from .scope import diff_scan_files, full_scan_files
from .validator_pool import validate_all


console = Console()


def _resolve_git_head(repo: Path) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(repo), "rev-parse", "--short", "HEAD"],
            text=True,
        ).strip()
    except Exception:
        return None


def _fp_for_candidate(cand: dict) -> str:
    return make_fingerprint(
        sink_type=cand.get("sink_type", "other"),
        file=str(cand.get("file", "")),
        snippet=str(cand.get("snippet", "")),
    )


async def _scan(
    *,
    repo: Path,
    mode: str,
    base: str | None,
    head: str | None,
    concurrency: int,
    report_out: Path,
    baseline_path: Path,
    skip_known_exclusions: bool,
) -> int:
    # 1. Determine scan scope
    if mode == "full":
        files = full_scan_files(repo)
    elif mode == "diff":
        if not (base and head):
            console.print("[red]--base and --head required for diff mode[/red]")
            return 2
        files = diff_scan_files(repo, base, head)
    else:
        console.print(f"[red]Unknown mode: {mode}[/red]")
        return 2

    if not files:
        console.print("[yellow]No source files in scope. Nothing to scan.[/yellow]")
        return 0

    console.print(f"[bold]Scan scope:[/bold] {len(files)} file(s) in {repo}")

    # 2. Scanner (Phase 1)
    console.print("[cyan]→ running Scanner agent(s)…[/cyan]")
    candidates = await run_scanner_batched(repo, files)
    console.print(f"[green]Scanner produced {len(candidates)} candidate(s).[/green]")

    if not candidates:
        # Ensure baseline.db exists (even empty) so downstream steps don't fail.
        baseline_path.parent.mkdir(parents=True, exist_ok=True)
        Baseline(baseline_path)
        _write_report(report_out, repo, [], [], mode, _resolve_git_head(repo))
        return 0

    # 3. Baseline dedup — skip candidates already excluded previously
    baseline = Baseline(baseline_path)
    to_validate: list[dict] = []
    reused: list[dict] = []
    for c in candidates:
        fp = _fp_for_candidate(c)
        c["_fingerprint"] = fp
        if skip_known_exclusions:
            prev = baseline.get(fp)
            if prev and prev["status"] == "excluded":
                reused.append(prev["payload"])
                continue
        to_validate.append(c)

    console.print(
        f"[cyan]→ Validator pool: validating {len(to_validate)} "
        f"(reused {len(reused)} prior exclusions)[/cyan]"
    )

    # 4. Validator fan-out
    validator_results = await validate_all(repo, to_validate, concurrency=concurrency)

    # 5. Split into confirmed / excluded, write to baseline
    confirmed: list[dict] = []
    excluded: list[dict] = list(reused)
    for cand, r in zip(to_validate, validator_results):
        fp = cand["_fingerprint"]
        r["_fingerprint"] = fp
        baseline.upsert(fp, r)
        if r.get("status") == "confirmed":
            confirmed.append(r)
        else:
            excluded.append(r)

    # 6. Report
    _write_report(report_out, repo, confirmed, excluded, mode, _resolve_git_head(repo))
    _print_summary(confirmed, excluded)
    return 0


def _write_report(
    out_path: Path,
    repo: Path,
    confirmed: list[dict],
    excluded: list[dict],
    mode: str,
    git_ref: str | None,
) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    md = render_markdown(
        repo=repo, confirmed=confirmed, excluded=excluded, mode=mode, git_ref=git_ref
    )
    out_path.write_text(md, encoding="utf-8")
    console.print(f"[green]Report written:[/green] {out_path}")


def _print_summary(confirmed: list[dict], excluded: list[dict]) -> None:
    t = Table(title="SAST Summary")
    t.add_column("Severity")
    t.add_column("Count", justify="right")
    sev_counts: dict[str, int] = {}
    for c in confirmed:
        s = (c.get("severity") or "MEDIUM").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1
    for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        t.add_row(s, str(sev_counts.get(s, 0)))
    t.add_row("Confirmed total", str(len(confirmed)))
    t.add_row("Excluded", str(len(excluded)))
    console.print(t)


# -------- CLI --------

@click.group()
def cli() -> None:
    """sast-agent — multi-agent SAST pipeline."""


@cli.command()
@click.option("--repo", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--mode", type=click.Choice(["full", "diff"]), default="full")
@click.option("--base", default=None, help="(diff mode) base git ref")
@click.option("--head", default=None, help="(diff mode) head git ref")
@click.option("--concurrency", default=5, show_default=True, help="Validator parallelism")
@click.option("--report", "report_out", type=click.Path(path_type=Path), default=None)
@click.option("--baseline", "baseline_path", type=click.Path(path_type=Path), default=None)
@click.option("--fresh", is_flag=True, help="Don't reuse prior exclusions from baseline")
def scan(
    repo: Path,
    mode: str,
    base: str | None,
    head: str | None,
    concurrency: int,
    report_out: Path | None,
    baseline_path: Path | None,
    fresh: bool,
) -> None:
    """Run scanner + validator pipeline."""
    repo = repo.resolve()
    report_out = report_out or (repo / ".sast-agent" / "report.md")
    baseline_path = baseline_path or (repo / ".sast-agent" / "baseline.db")
    rc = anyio.run(functools.partial(
        _scan,
        repo=repo,
        mode=mode,
        base=base,
        head=head,
        concurrency=concurrency,
        report_out=report_out,
        baseline_path=baseline_path,
        skip_known_exclusions=not fresh,
    ))
    sys.exit(rc or 0)


@cli.command()
@click.option("--repo", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
def report(repo: Path) -> None:
    """Re-render the report from the stored baseline without re-scanning."""
    repo = repo.resolve()
    baseline_path = repo / ".sast-agent" / "baseline.db"
    if not baseline_path.exists():
        console.print("[red]No baseline found. Run `sast-agent scan` first.[/red]")
        sys.exit(1)
    bl = Baseline(baseline_path)
    md = render_markdown(
        repo=repo,
        confirmed=bl.all_confirmed(),
        excluded=bl.all_excluded(),
        mode="cached",
        git_ref=_resolve_git_head(repo),
    )
    out = repo / ".sast-agent" / "report.md"
    out.write_text(md, encoding="utf-8")
    console.print(f"[green]Report written:[/green] {out}")


@cli.command()
@click.option("--repo", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--host", default="127.0.0.1", show_default=True, help="Bind address (keep 127.0.0.1 for safety)")
@click.option("--port", default=8765, show_default=True, type=int)
@click.option("--open-browser/--no-open-browser", default=True, show_default=True)
def ui(repo: Path, host: str, port: int, open_browser: bool) -> None:
    """Launch local read-only web viewer over baseline.db."""
    import webbrowser
    import uvicorn
    from .ui import create_app

    repo = repo.resolve()
    try:
        app = create_app(repo)
    except FileNotFoundError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)

    url = f"http://{host}:{port}"
    console.print(f"[green]sast-agent UI:[/green] {url}  (read-only, Ctrl-C to stop)")
    if open_browser:
        try:
            webbrowser.open(url)
        except Exception:
            pass
    uvicorn.run(app, host=host, port=port, log_level="warning")


@cli.command("dump-candidates")
@click.option("--repo", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--mode", type=click.Choice(["full", "diff"]), default="full")
@click.option("--base", default=None)
@click.option("--head", default=None)
def dump_candidates(repo: Path, mode: str, base: str | None, head: str | None) -> None:
    """Run only the Scanner and dump raw candidate JSON. Useful for debugging."""

    async def _do() -> None:
        files = (
            full_scan_files(repo) if mode == "full"
            else diff_scan_files(repo, base or "HEAD~1", head or "HEAD")
        )
        cands = await run_scanner_batched(repo, files)
        click.echo(json.dumps({"candidates": cands}, ensure_ascii=False, indent=2))

    anyio.run(_do)


# ---------- fix / github integration ----------

def _short_fp(fp: str, n: int = 10) -> str:
    return (fp or "nofp")[:n]


async def _fix_pipeline(
    *,
    repo: Path,
    baseline_path: Path,
    concurrency: int,
    push: bool,
    create_prs: bool,
    base_branch: str,
    limit: int | None,
) -> int:
    if not baseline_path.exists():
        console.print(f"[yellow]No baseline at {baseline_path}. Nothing to fix.[/yellow]")
        return 0

    bl = Baseline(baseline_path)
    findings = bl.all_confirmed()
    # ensure fingerprint is in each finding (baseline stores it in payload if we set it at scan time)
    for f in findings:
        if "_fingerprint" not in f:
            f["_fingerprint"] = make_fingerprint(
                sink_type=f.get("sink_type", "other"),
                file=str(f.get("file", "")),
                snippet=str(f.get("snippet", "")),
            )
    if limit:
        findings = findings[:limit]

    if not findings:
        console.print("[yellow]No confirmed findings to fix.[/yellow]")
        return 0

    console.print(f"[bold]Fix pipeline:[/bold] {len(findings)} confirmed finding(s)")

    # 1. Generate diffs (parallel, read-only)
    original_branch = gh_ops.current_branch(repo)
    console.print(f"[cyan]→ running Fixer agents (concurrency={concurrency})…[/cyan]")
    fixes = await fix_all(repo, findings, concurrency=concurrency)

    summary: list[dict] = []
    for finding, fix in zip(findings, fixes):
        fp = finding.get("_fingerprint") or fix.get("_fingerprint") or "nofp"
        short = _short_fp(fp)
        title = finding.get("title") or finding.get("sink_type") or "finding"
        entry: dict = {
            "fingerprint": fp, "title": title, "file": finding.get("file"),
            "branch": None, "applied": False, "reviewer_verdict": None,
            "pr_url": None, "error": fix.get("error"),
        }

        if not fix.get("diff"):
            console.print(f"[yellow]  skip {short}: no diff ({fix.get('error') or 'empty'})[/yellow]")
            summary.append(entry)
            continue

        branch = f"sast-fix/{short}"
        entry["branch"] = branch
        # 2. Checkout new branch, apply, commit
        try:
            gh_ops.create_branch(repo, branch, from_ref=base_branch if _ref_exists(repo, base_branch) else None)
        except gh_ops.GitError as e:
            # branch may exist already — skip this finding
            console.print(f"[yellow]  skip {short}: branch error: {e}[/yellow]")
            entry["error"] = str(e)
            summary.append(entry)
            continue

        try:
            gh_ops.apply_patch(repo, fix["diff"])
            commit_sha = gh_ops.commit_all(
                repo, f"SAST fix: {finding.get('sink_type','?')} in {finding.get('file','?')}"
            )
            entry["applied"] = True
            console.print(f"[green]  applied {short} → {branch}@{commit_sha}[/green]")
        except gh_ops.GitError as e:
            console.print(f"[red]  apply failed {short}: {e}[/red]")
            entry["error"] = str(e)
            gh_ops.checkout(repo, original_branch)
            summary.append(entry)
            continue

        # 3. Reviewer on patched state
        console.print(f"[cyan]    → Reviewer re-validating {short}…[/cyan]")
        rev_result = await review_one(repo, finding, fix)
        verdict = coerce_verdict(rev_result)
        entry["reviewer_verdict"] = verdict.get("verdict")
        console.print(f"    reviewer: [bold]{verdict.get('verdict')}[/bold]")

        # 4. Optional push + PR
        if push:
            try:
                gh_ops.push(repo, branch)
            except gh_ops.GitError as e:
                console.print(f"[red]    push failed: {e}[/red]")
                entry["error"] = str(e)

        if create_prs:
            body = _fix_pr_body(finding, fix, verdict)
            body_file = baseline_path.parent / f"_prbody_{short}.md"
            body_file.write_text(body, encoding="utf-8")
            try:
                pr = gh_ops.pr_create(
                    repo, base=base_branch, head=branch,
                    title=f"SAST: fix {finding.get('sink_type','issue')} in {finding.get('file','?')}",
                    body_file=body_file,
                )
                entry["pr_url"] = pr.url
                console.print(f"[green]    PR: {pr.url}[/green]")
            except gh_ops.GhError as e:
                console.print(f"[red]    PR create failed: {e}[/red]")
                entry["error"] = str(e)
            finally:
                body_file.unlink(missing_ok=True)

        # return to origin branch before next iteration
        gh_ops.checkout(repo, original_branch)
        summary.append(entry)

    _print_fix_summary(summary)
    return 0


def _ref_exists(repo: Path, ref: str) -> bool:
    p = gh_ops.git(repo, "rev-parse", "--verify", ref, check=False)
    return p.returncode == 0


def _fix_pr_body(finding: dict, fix: dict, verdict: dict) -> str:
    lines = [
        "## SAST auto-generated fix — ⚠️ requires human review",
        "",
        f"**Sink**: `{finding.get('sink_type')}`  ·  **Severity**: `{finding.get('severity','?')}`  ·  **File**: `{finding.get('file')}:{finding.get('line') or '?'}`",
        "",
        "### Original finding",
        f"- Title: {finding.get('title','?')}",
        f"- Reproduction: {finding.get('reproduction','—')}",
        f"- Impact: {finding.get('impact','—')}",
        "",
        "### Fixer",
        f"- Pattern: `{fix.get('fix_pattern','?')}`",
        f"- Risk: `{fix.get('breaking_change_risk','?')}`",
        f"- Explanation: {fix.get('explanation','—')}",
        "",
        "### Reviewer verdict",
        f"- **{verdict.get('verdict','?')}**",
        f"- vuln eliminated: `{verdict.get('original_vuln_eliminated')}`",
        f"- notes: {verdict.get('notes') or verdict.get('reason') or '—'}",
        "",
        "---",
        "_Generated by sast-agent. Do not merge without human review._",
    ]
    return "\n".join(lines)


def _print_fix_summary(summary: list[dict]) -> None:
    t = Table(title="Fix Pipeline Summary")
    t.add_column("Short")
    t.add_column("Title")
    t.add_column("Applied")
    t.add_column("Reviewer")
    t.add_column("PR")
    for row in summary:
        t.add_row(
            _short_fp(row["fingerprint"]),
            (row["title"] or "")[:32],
            "yes" if row["applied"] else "—",
            row["reviewer_verdict"] or (row["error"] or "—")[:20],
            row["pr_url"] or "—",
        )
    console.print(t)


@cli.command()
@click.option("--repo", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--baseline", "baseline_path", type=click.Path(path_type=Path), default=None)
@click.option("--concurrency", default=3, show_default=True, type=int)
@click.option("--push/--no-push", default=False, show_default=True, help="Push fix branch to origin")
@click.option("--create-prs/--no-create-prs", default=False, show_default=True, help="Open GitHub PR per fix (requires gh auth + --push)")
@click.option("--base-branch", default="main", show_default=True)
@click.option("--limit", type=int, default=None, help="Only fix first N confirmed findings")
def fix(
    repo: Path, baseline_path: Path | None, concurrency: int,
    push: bool, create_prs: bool, base_branch: str, limit: int | None,
) -> None:
    """Generate + apply fixes for confirmed findings, each on its own branch,
    then run Reviewer for independent re-validation. Optionally push and open PRs."""
    repo = repo.resolve()
    baseline_path = baseline_path or (repo / ".sast-agent" / "baseline.db")
    if create_prs and not push:
        console.print("[yellow]--create-prs implies --push; enabling --push[/yellow]")
        push = True
    rc = anyio.run(functools.partial(
        _fix_pipeline,
        repo=repo,
        baseline_path=baseline_path,
        concurrency=concurrency,
        push=push,
        create_prs=create_prs,
        base_branch=base_branch,
        limit=limit,
    ))
    sys.exit(rc or 0)


@cli.command("gh-pr-comment")
@click.option("--repo", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--pr", "pr_number", type=int, required=True)
@click.option("--report", "report_path", type=click.Path(path_type=Path), default=None,
              help="Path to report.md (defaults to <repo>/.sast-agent/report.md)")
def gh_pr_comment(repo: Path, pr_number: int, report_path: Path | None) -> None:
    """Post the rendered Markdown report as a comment on a GitHub PR (via gh)."""
    repo = repo.resolve()
    report_path = report_path or (repo / ".sast-agent" / "report.md")
    if not report_path.exists():
        console.print(f"[red]Report not found: {report_path}[/red]")
        sys.exit(1)
    try:
        gh_ops.pr_comment(repo, pr_number, report_path)
    except gh_ops.GhError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    console.print(f"[green]Posted report to PR #{pr_number}.[/green]")


@cli.command("gh-issue")
@click.option("--repo", type=click.Path(exists=True, file_okay=False, path_type=Path), required=True)
@click.option("--title", default=None, help="Issue title (default auto-generated)")
@click.option("--report", "report_path", type=click.Path(path_type=Path), default=None)
@click.option("--label", default="sast", show_default=True)
def gh_issue(repo: Path, title: str | None, report_path: Path | None, label: str) -> None:
    """Open a GitHub Issue with the current report (used by weekly cron)."""
    repo = repo.resolve()
    report_path = report_path or (repo / ".sast-agent" / "report.md")
    if not report_path.exists():
        console.print(f"[red]Report not found: {report_path}[/red]")
        sys.exit(1)
    ref = _resolve_git_head(repo) or "?"
    issue_title = title or f"SAST weekly report — {ref}"
    try:
        url = gh_ops.issue_create(repo, title=issue_title, body_file=report_path, label=label)
    except gh_ops.GhError as e:
        console.print(f"[red]{e}[/red]")
        sys.exit(1)
    console.print(f"[green]Opened issue: {url}[/green]")


if __name__ == "__main__":
    cli()
