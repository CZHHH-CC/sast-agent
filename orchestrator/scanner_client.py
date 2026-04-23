"""Invoke the Scanner agent against a bounded set of files."""

from __future__ import annotations

from pathlib import Path

from .agent_runtime import AgentResult, run_agent
from .scope import cluster_by_directory


SCANNER_TOOLS = ["Glob", "Grep", "Read", "FindFunction", "FindCallers", "FindImports"]
SCANNER_SKILL_REFS = ["references/sink-patterns.md"]

# Tuning (see plan P1-4):
#   - Smaller batches (12) → lower chance of a single no_json_found wiping out
#     many files' coverage; higher chance LLM fits everything in one response.
#   - Higher turn budget (60) → Read/Grep over 10–15 files comfortably.
DEFAULT_SCANNER_BATCH_SIZE = 12
DEFAULT_SCANNER_MAX_TURNS = 60


def _build_user_prompt(repo: Path, files: list[Path]) -> str:
    rel = [str(p.relative_to(repo)).replace("\\", "/") for p in files]
    file_list = "\n".join(f"- {r}" for r in rel)
    return f"""对以下文件执行 SAST Phase 1（广撒网）。输出 JSON。

仓库根目录: {repo}
待扫描文件（{len(rel)} 个，通常属于同一模块/目录，可视为一个协同单元）:
{file_list}

要求：
- 对每个文件用 Read 读取内容（大文件可以用 offset/limit 翻页）
- 识别所有可能的危险 sink 候选，参考 sink-patterns.md 的核心概念和判定原则
- 不判断可达性、不判断可利用性、不判断误报 —— 宁可多报
- 同模块内若发现跨文件 source→sink 线索，可以在 candidate 中引用多个 file/line
- 只输出 JSON 候选清单，遵守 Scanner 系统提示中定义的格式
"""


async def run_scanner(
    repo: Path, files: list[Path], *, max_turns: int = DEFAULT_SCANNER_MAX_TURNS
) -> AgentResult:
    if not files:
        return AgentResult(raw_text='{"candidates": []}', parsed={"candidates": []})

    prompt = _build_user_prompt(repo, files)
    return await run_agent(
        role="scanner",
        user_prompt=prompt,
        cwd=repo,
        allowed_tools=SCANNER_TOOLS,
        skill_refs=SCANNER_SKILL_REFS,
        max_turns=max_turns,
    )


async def run_scanner_batched(
    repo: Path,
    files: list[Path],
    batch_size: int = DEFAULT_SCANNER_BATCH_SIZE,
    *,
    max_turns: int = DEFAULT_SCANNER_MAX_TURNS,
) -> list[dict]:
    """Scan in batches to stay under context limits. Returns merged candidate list.

    Batches are built by directory clustering (see scope.cluster_by_directory)
    so same-module files share a Scanner window — preserves cross-file signal
    that a pure slice-every-N strategy would lose.

    Raises RuntimeError if every batch failed with an LLM error so users don't
    mistake an infra failure for a clean codebase.
    """
    if not files:
        return []

    batches = cluster_by_directory(files, target_batch_size=batch_size)
    all_candidates: list[dict] = []
    errors: list[str] = []
    for batch_idx, batch in enumerate(batches):
        result = await run_scanner(repo, batch, max_turns=max_turns)
        if result.error:
            errors.append(result.error)
            print(f"  [scanner batch {batch_idx}] error: {result.error}")
        if result.parsed and isinstance(result.parsed.get("candidates"), list):
            for idx, cand in enumerate(result.parsed["candidates"]):
                cand["id"] = f"b{batch_idx}_{cand.get('id', idx)}"
                all_candidates.append(cand)

    if errors and len(errors) == len(batches) and not all_candidates:
        raise RuntimeError(
            f"Scanner failed on all {len(batches)} batch(es). "
            f"First error: {errors[0]}"
        )
    return all_candidates
