# sast-agent

Multi-agent SAST pipeline — provider-agnostic (Anthropic / OpenAI / OpenAI-compatible), self-implemented tool sandbox.

## What it does

Runs the `sast-audit` methodology (5 phases: broad scan → reachability → mitigation → exploitability → design vs. bug) as a pipeline of specialized agents, so each stage gets its own context window and can run in parallel.

**Agents:**

| Agent | Role | Phase |
|---|---|---|
| Scanner | Broad sink discovery (JSON candidate list) | Phase 1 |
| Validator × N | Per-candidate 5-phase verification | Phase 2-5 |
| Fixer × M | Minimal-change fix patch | — |
| Reviewer | Re-validate after fix | Phase 2-5 |

## MVP scope (this version)

- ✅ Scanner + Validator, local CLI
- ✅ Baseline (SQLite) + fingerprint-based dedup
- ✅ Markdown report matching `sast-audit/references/report-template.md`
- ✅ Local read-only web viewer (`sast-agent ui`)
- ✅ Fixer + Reviewer pipeline (`sast-agent fix`), optionally pushes branches + opens PRs
- ✅ GitHub Actions workflows: PR / weekly cron / manual dispatch

## Install

```bash
cd D:\AI\sast-agent
python -m venv .venv
.venv\Scripts\activate            # (Windows; on *nix use source .venv/bin/activate)
pip install -e .
```

### Provider selection

sast-agent is **provider-agnostic**. Pick one:

| Provider | Env vars | Notes |
|---|---|---|
| Anthropic | `ANTHROPIC_API_KEY`, optional `SAST_ANTHROPIC_MODEL` (default `claude-sonnet-4-5`) | Default when `ANTHROPIC_API_KEY` is set |
| OpenAI | `OPENAI_API_KEY`, optional `SAST_OPENAI_MODEL` (default `gpt-4o`) | |
| OpenAI-compatible (DeepSeek / Moonshot / Together / vLLM / Ollama's `/v1`) | `OPENAI_API_KEY`, `SAST_OPENAI_BASE_URL=https://...` , `SAST_OPENAI_MODEL=<model>` | Anything that speaks the OpenAI tool-calling shape |

Explicit override: `SAST_PROVIDER=anthropic` or `SAST_PROVIDER=openai`.

The model **must support tool use / function calling** — the whole pipeline
depends on the agent issuing `Read` / `Grep` / `Glob` tool calls to inspect
the code. Text-only models won't work.

## Verify install (no API calls)

```bash
python scripts/smoke_test.py
# should print "ALL SMOKE TESTS PASSED"
```

This exercises fingerprint stability, scope enumeration, baseline round-trip,
and report rendering — all **without** calling the Claude API.

## Usage

```bash
# Full scan of the bundled intentionally-vulnerable fixture
sast-agent scan --repo ./testfixtures/vulnerable-java --mode full

# Incremental scan against a git diff (PR-style)
sast-agent scan --repo <path> --mode diff --base main --head HEAD

# Debug: dump Scanner candidates only, skip Validator
sast-agent dump-candidates --repo ./testfixtures/vulnerable-java --mode full

# Re-render report from existing baseline without re-scanning
sast-agent report --repo <path>

# Browse findings in a local web UI (read-only, binds 127.0.0.1 only)
sast-agent ui --repo <path>

# Generate + apply fix branches for every confirmed finding, plus Reviewer re-validation.
# Dry run (no push, no PR): just creates sast-fix/<fp> branches locally.
sast-agent fix --repo <path>

# Full: push branches and open PRs via gh (requires `gh auth login` + remote).
sast-agent fix --repo <path> --push --create-prs --base-branch main

# GitHub helpers used by workflows
sast-agent gh-pr-comment --repo <path> --pr 42      # post report.md as PR comment
sast-agent gh-issue      --repo <path>              # open weekly-cron Issue
```

### Expected output on the fixture

Running `scan --mode full` on `testfixtures/vulnerable-java` should produce:

- **2 confirmed**: `SearchController` (SQL injection, CRITICAL), `CommandRunner` (command injection, HIGH)
- **≥2 excluded**: `EntityManagerUtil` (dead_code), `LoginVo` (swagger_example)
- `SafeUserDao` should be cleanly absent (safe counter-example)

Report lands at `./testfixtures/vulnerable-java/.sast-agent/report.md`.
Baseline SQLite lands at `./testfixtures/vulnerable-java/.sast-agent/baseline.db`.

### Tuning

| Flag | Purpose |
|---|---|
| `--concurrency N` | Validator parallelism (default 5). Raise for speed, lower for cost. |
| `--fresh` | Ignore prior exclusions in the baseline; re-validate everything. |
| `--report <path>` | Override report output path. |
| `--baseline <path>` | Override baseline DB path. |

## GitHub Actions

Three workflows are shipped in `.github/workflows/`:

| File | Trigger | What it does |
|---|---|---|
| `sast-pr.yml` | `pull_request` | Diff-mode scan; posts report as PR comment |
| `sast-weekly.yml` | Cron (Sun 00:00 UTC) + `workflow_dispatch` | Full scan; opens Issue; commits baseline to `sast-baseline` branch |
| `sast-manual.yml` | `workflow_dispatch` | On-demand full/diff scan with optional fix-PR generation |

### Required secrets / vars

Set **at least one** LLM provider secret in the repo's `Settings → Secrets → Actions`:

| Name | Scope | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | secret | Anthropic provider |
| `OPENAI_API_KEY` | secret | OpenAI / OpenAI-compatible provider |
| `SAST_OPENAI_BASE_URL` | secret | (optional) base URL for OpenAI-compatible endpoint |
| `SAST_ANTHROPIC_MODEL` | variable | (optional) override default Anthropic model |
| `SAST_OPENAI_MODEL` | variable | (optional) override default OpenAI model |
| `SAST_PROVIDER` | variable | (optional) force `anthropic` or `openai` |

`GITHUB_TOKEN` is injected automatically; the workflows request `pull-requests: write`, `contents: write`, `issues: write` in their `permissions:` blocks as needed.

### Fix PRs require human review

The `fix` job in `sast-manual.yml` creates one branch per confirmed finding under `sast-fix/<fingerprint-short>` and opens a PR with the Reviewer agent's verdict in the body. **No auto-merge is configured** — always gate on human review.

## Layout

```
orchestrator/   # Python control plane (non-LLM)
agents/         # System prompts for each LLM agent
skills/         # Bundled sast-audit skill (vendored)
testfixtures/   # Intentionally vulnerable sample repos
.github/workflows/  # sast-pr.yml / sast-weekly.yml / sast-manual.yml
```

## Design

See `C:\Users\97295\.claude\plans\transient-popping-hummingbird.md` for full architecture.
