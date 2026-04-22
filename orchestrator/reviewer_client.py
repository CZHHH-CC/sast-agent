"""Invoke the Reviewer agent on the post-fix state of the repo.

Reviewer is Validator-flavored: read-only, re-runs the 5-phase check on
the patched code to verify the vulnerability is actually gone and no new
issues were introduced.
"""

from __future__ import annotations

import json
from pathlib import Path

from .agent_runtime import AgentResult, run_agent


REVIEWER_TOOLS = ["Glob", "Grep", "Read"]
REVIEWER_SKILL_REFS = [
    "SKILL.md",
    "references/false-positive-patterns.md",
]


def _build_user_prompt(repo: Path, original_finding: dict, fix: dict) -> str:
    return f"""对已应用修复的代码进行独立复核（Reviewer）。

仓库根目录: {repo}（代码已应用修复 diff，直接 Read 即可看到修复后状态）

原漏洞 JSON:
```json
{json.dumps(original_finding, ensure_ascii=False, indent=2)}
```

Fixer 的修复说明:
```json
{json.dumps({
    "fix_pattern": fix.get("fix_pattern"),
    "explanation": fix.get("explanation"),
    "files_changed": fix.get("files_changed"),
    "breaking_change_risk": fix.get("breaking_change_risk"),
}, ensure_ascii=False, indent=2)}
```

要求：
- **不**依赖 Fixer 的说明，自己 Read 修复后的文件判断
- 对原漏洞位置重跑 Validator 5 阶段 —— 还能利用吗？
- Grep 同 sink_type 的其他位置 —— 这次修复是否遗漏？
- 功能回归风险：接口行为是否变化？
- 严格按 Reviewer 系统提示中的两种 JSON 格式之一输出（approved / approved_with_notes / rejected）
"""


async def review_one(
    repo: Path, original_finding: dict, fix: dict, *, max_turns: int = 20,
) -> AgentResult:
    return await run_agent(
        role="reviewer",
        user_prompt=_build_user_prompt(repo, original_finding, fix),
        cwd=repo,
        allowed_tools=REVIEWER_TOOLS,
        skill_refs=REVIEWER_SKILL_REFS,
        max_turns=max_turns,
    )


def coerce_verdict(result: AgentResult) -> dict:
    """Normalize reviewer output into a dict with a `verdict` string."""
    if result.parsed and isinstance(result.parsed, dict) and "verdict" in result.parsed:
        return result.parsed
    return {
        "verdict": "error",
        "original_vuln_eliminated": None,
        "reason": f"reviewer produced no parseable JSON ({result.error})",
        "raw_text": (result.raw_text or "")[:2000],
    }
