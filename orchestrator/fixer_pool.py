"""Run N Fixer agents in parallel, one per confirmed finding.

Fixer is read-only from the code-inspection perspective — it outputs a
unified diff **as text** in its JSON. The orchestrator (not the agent)
applies the diff via `git apply`. This keeps the LLM tool surface small
and lets us sandbox writes to git operations we control.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .agent_runtime import AgentResult, run_agent


FIXER_TOOLS = ["Glob", "Grep", "Read"]
FIXER_SKILL_REFS: list[str] = []  # Fixer prompt is self-contained


def _build_user_prompt(repo: Path, finding: dict) -> str:
    return f"""为以下确认漏洞生成最小修复 diff。

仓库根目录: {repo}

漏洞 JSON（来自 Validator）:
```json
{json.dumps(finding, ensure_ascii=False, indent=2)}
```

要求：
- 先用 Read 把漏洞相关文件完整读一遍，理解上下文
- 必要时用 Grep 找同模式的其他位置（但本任务只改当前这一处）
- 只改漏洞涉及的语句 + 必要 import
- 不改函数签名、不改返回值语义
- 输出 JSON：至少包含 `files_changed` / `fix_pattern` / `explanation` / `diff` / `breaking_change_risk` 字段
- `diff` 必须是 **git apply** 能直接吃的 unified diff（`--- a/...` / `+++ b/...` 头 + `@@` hunk 标记），路径相对仓库根目录
"""


async def fix_one(
    repo: Path, finding: dict, *, sem: asyncio.Semaphore, max_turns: int = 20,
) -> AgentResult:
    async with sem:
        return await run_agent(
            role="fixer",
            user_prompt=_build_user_prompt(repo, finding),
            cwd=repo,
            allowed_tools=FIXER_TOOLS,
            skill_refs=FIXER_SKILL_REFS,
            max_turns=max_turns,
        )


async def fix_all(
    repo: Path, findings: list[dict], *, concurrency: int = 3,
) -> list[dict]:
    """Run fixers concurrently. Returns list of parsed fixer JSON (or an error
    shape on parse failure). Same length as `findings`."""
    if not findings:
        return []
    sem = asyncio.Semaphore(concurrency)
    tasks = [fix_one(repo, f, sem=sem) for f in findings]
    results: list[AgentResult] = await asyncio.gather(*tasks)

    out: list[dict] = []
    for f, r in zip(findings, results):
        if r.parsed and isinstance(r.parsed.get("diff"), str) and r.parsed["diff"].strip():
            r.parsed.setdefault("candidate_id", f.get("candidate_id") or f.get("_fingerprint"))
            r.parsed.setdefault("_fingerprint", f.get("_fingerprint"))
            out.append(r.parsed)
        else:
            out.append({
                "_fingerprint": f.get("_fingerprint"),
                "candidate_id": f.get("candidate_id"),
                "error": r.error or "no_diff_in_output",
                "raw_text": (r.raw_text or "")[:2000],
                "fix_pattern": "other",
                "explanation": "fixer produced no applicable diff",
                "diff": "",
                "needs_human_review": True,
            })
    return out
