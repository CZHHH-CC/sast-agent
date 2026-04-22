"""Run N Validator agents in parallel, one per candidate."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from .agent_runtime import AgentResult, run_agent


VALIDATOR_TOOLS = ["Glob", "Grep", "Read"]
VALIDATOR_SKILL_REFS = [
    "SKILL.md",
    "references/false-positive-patterns.md",
]


def _build_user_prompt(repo: Path, candidate: dict) -> str:
    return f"""对以下候选执行 SAST Phase 2-5 验证。

仓库根目录: {repo}

候选 JSON:
```json
{json.dumps(candidate, ensure_ascii=False, indent=2)}
```

要求：
- 证伪优先：尝试所有理由排除它
- 每一项 verified_evidence 必须有代码查证，不能用"可能""推测"
- 任一 Phase 排除 → 直接输出 excluded，不继续后面的 Phase
- 只输出 JSON，遵守 Validator 系统提示中定义的两种格式之一（confirmed 或 excluded）
"""


async def validate_one(
    repo: Path, candidate: dict, *, sem: asyncio.Semaphore
) -> AgentResult:
    async with sem:
        return await run_agent(
            role="validator",
            user_prompt=_build_user_prompt(repo, candidate),
            cwd=repo,
            allowed_tools=VALIDATOR_TOOLS,
            skill_refs=VALIDATOR_SKILL_REFS,
            max_turns=30,
        )


async def validate_all(
    repo: Path, candidates: list[dict], *, concurrency: int = 5
) -> list[dict]:
    """Run validators concurrently. Returns list of parsed validator JSON outputs
    (each is either a `confirmed` or `excluded` shape). Candidates that fail to
    parse are coerced into an `excluded` with category `over_inference` so they
    don't silently vanish."""
    if not candidates:
        return []

    sem = asyncio.Semaphore(concurrency)
    tasks = [validate_one(repo, c, sem=sem) for c in candidates]
    results: list[AgentResult] = await asyncio.gather(*tasks)

    out: list[dict] = []
    for cand, res in zip(candidates, results):
        if res.parsed and "status" in res.parsed:
            # copy candidate fields through if validator omitted them
            res.parsed.setdefault("file", cand.get("file"))
            res.parsed.setdefault("line", cand.get("line"))
            res.parsed.setdefault("sink_type", cand.get("sink_type"))
            res.parsed.setdefault("snippet", cand.get("snippet"))
            res.parsed.setdefault("candidate_id", cand.get("id"))
            out.append(res.parsed)
        else:
            out.append({
                "status": "excluded",
                "candidate_id": cand.get("id"),
                "exclusion_category": "over_inference",
                "reason": f"validator produced no parseable JSON ({res.error})",
                "evidence": "",
                "file": cand.get("file"),
                "line": cand.get("line"),
                "sink_type": cand.get("sink_type"),
                "snippet": cand.get("snippet"),
            })
    return out
