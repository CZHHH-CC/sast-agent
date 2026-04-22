# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`sast-agent` is a multi-agent SAST (Static Application Security Testing) pipeline. It uses LLM agents (Scanner → Validator → Fixer → Reviewer) to find and fix security vulnerabilities in source code. The tool is provider-agnostic and runs on Anthropic or OpenAI APIs.

## Setup & Install

```bash
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e .
```

Entry point after install: `sast-agent`

## Common Commands

```bash
# Run offline smoke tests (no API calls needed)
python scripts/smoke_test.py

# Scan a repo
sast-agent scan --repo <path> --mode full
sast-agent scan --repo <path> --mode diff --concurrency 5

# Re-render report from existing baseline
sast-agent report --repo <path>

# Launch local web viewer (localhost:8765)
sast-agent ui --repo <path>

# Generate fixes and optionally push PRs
sast-agent fix --repo <path> [--push] [--create-prs]

# Dump raw candidates without validation
sast-agent dump-candidates --repo <path> --mode full
```

## Architecture

### Agent Pipeline

```
Scanner → [candidates JSON]
           → ValidatorPool (parallel, default 5 workers) → confirmed findings
                                                          → BaselineDB (SQLite)
                                                          → report.md
           (optional) → FixerPool → ReviewerClient → branch/PR push
```

All agents share the same runtime (`orchestrator/agent_runtime.py`). Agents get three sandboxed tools: **Read**, **Glob**, **Grep** — all path-restricted to the scan root.

### Key Files

| File | Role |
|------|------|
| `orchestrator/main.py` | Click CLI entrypoint |
| `orchestrator/agent_runtime.py` | Provider-agnostic tool-use loop (up to 25 turns) |
| `orchestrator/scanner_client.py` | Scanner agent orchestration |
| `orchestrator/validator_pool.py` | Concurrent validator agent pool |
| `orchestrator/fixer_pool.py` | Concurrent fixer agent pool |
| `orchestrator/reviewer_client.py` | Post-fix reviewer agent |
| `orchestrator/llm/` | Provider adapters (Anthropic, OpenAI) + factory |
| `orchestrator/tools/registry.py` | Tool sandbox (Read/Glob/Grep) |
| `orchestrator/baseline.py` | SQLite baseline CRUD |
| `orchestrator/fingerprint.py` | Deterministic 16-char hex fingerprints |
| `orchestrator/scope.py` | File enumeration (full or diff mode) |
| `orchestrator/report.py` | Markdown report rendering |
| `orchestrator/github.py` | Git/`gh` CLI wrappers |
| `agents/*.md` | System prompts for each agent role (written in Chinese) |
| `skills/sast-audit/SKILL.md` | Full 5-phase audit methodology |

### LLM Provider Abstraction

`orchestrator/llm/base.py` defines `LLMClient` with `Message`, `ToolCall`, `ToolResult`, `LLMResponse`. Factory (`llm/factory.py`) selects provider from env:

1. `SAST_PROVIDER=anthropic|openai` (explicit override)
2. `ANTHROPIC_API_KEY` present → Anthropic (default model: `claude-sonnet-4-5`)
3. `OPENAI_API_KEY` present → OpenAI (default model: `gpt-4o`)

Optional overrides: `SAST_ANTHROPIC_MODEL`, `SAST_OPENAI_MODEL`, `SAST_OPENAI_BASE_URL`.

### Baseline & Fingerprinting

- SQLite database at `<repo>/.sast-agent/baseline.db`
- Fingerprints are SHA256-based 16-char hex, normalized to survive line-number drift and whitespace changes
- Re-validation is skipped for known exclusions unless `--fresh` is passed

### Tool Sandbox

`tools/registry.py` restricts all file access to within the scan root. Tool output is capped at 30,000 chars. Glob caps at 500 results; Grep caps at 100 results.

### GitHub Actions

Three workflows in `.github/workflows/`:
- `sast-pr.yml`: Diff scan on PRs, posts `report.md` as PR comment
- `sast-weekly.yml`: Full scan weekly (Sun 00:00 UTC), opens GitHub Issue
- `sast-manual.yml`: On-demand, supports fix-PR generation

## Scan Scope

**Included extensions**: `.java`, `.kt`, `.scala`, `.groovy`, `.js`, `.ts`, `.jsx`, `.tsx`, `.py`, `.go`, `.rb`, `.php`, `.cs`, `.rs`, `.vue`, `.svelte`

**Excluded directories**: `.git`, `node_modules`, `vendor`, `target`, `build`, `__pycache__`, `.venv`, `.next`, `testfixtures`

## Test Fixtures

`testfixtures/vulnerable-java/` contains an intentionally vulnerable Java project. Expected results on a full scan:
- **2 confirmed**: SQL injection in `SearchController`, command injection in `CommandRunner`
- **≥2 excluded**: Dead code in `EntityManagerUtil`, false positive in `LoginVo` swagger annotation
- **Clean**: `SafeUserDao` should produce no findings
