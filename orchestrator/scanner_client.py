"""Invoke the Scanner agent against a bounded set of files."""

from __future__ import annotations

from pathlib import Path

from .agent_runtime import AgentResult, run_agent


SCANNER_TOOLS = ["Glob", "Grep", "Read"]
SCANNER_SKILL_REFS = ["references/sink-patterns.md"]


def _build_user_prompt(repo: Path, files: list[Path]) -> str:
    rel = [str(p.relative_to(repo)).replace("\\", "/") for p in files]
    file_list = "\n".join(f"- {r}" for r in rel)
    return f"""对以下文件执行 SAST Phase 1（广撒网）。输出 JSON。

仓库根目录: {repo}
待扫描文件（{len(rel)} 个）:
{file_list}

要求：
- 对每个文件用 Read 读取内容
- 识别所有可能的危险 sink 候选，参考 sink-patterns.md 的核心概念和判定原则
- 不判断可达性、不判断可利用性、不判断误报 —— 宁可多报
- 只输出 JSON 候选清单，遵守 Scanner 系统提示中定义的格式
"""


async def run_scanner(repo: Path, files: list[Path]) -> AgentResult:
    if not files:
        return AgentResult(raw_text='{"candidates": []}', parsed={"candidates": []})

    prompt = _build_user_prompt(repo, files)
    return await run_agent(
        role="scanner",
        user_prompt=prompt,
        cwd=repo,
        allowed_tools=SCANNER_TOOLS,
        skill_refs=SCANNER_SKILL_REFS,
        max_turns=40,
    )


async def run_scanner_batched(
    repo: Path, files: list[Path], batch_size: int = 40
) -> list[dict]:
    """Scan in batches to stay under context limits. Returns merged candidate list."""
    all_candidates: list[dict] = []
    for i in range(0, len(files), batch_size):
        batch = files[i : i + batch_size]
        result = await run_scanner(repo, batch)
        if result.parsed and isinstance(result.parsed.get("candidates"), list):
            # tag candidates with batch offset to avoid id collision
            for idx, cand in enumerate(result.parsed["candidates"]):
                cand["id"] = f"b{i}_{cand.get('id', idx)}"
                all_candidates.append(cand)
    return all_candidates
