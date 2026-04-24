"""Invoke the Scanner agent against a bounded set of files."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .agent_runtime import AgentResult, run_agent
from .scope import cluster_by_directory


@dataclass
class ScannerBatchResult:
    """Return value of ``run_scanner_batched`` (B1).

    Carries the merged candidate list plus aggregate token usage across every
    batch's LLM turns so the caller can print a per-phase cost breakdown.
    """
    candidates: list[dict] = field(default_factory=list)
    usage: dict[str, int] = field(default_factory=dict)
    calls: int = 0
    batches: int = 0


SCANNER_TOOLS = ["Glob", "Grep", "Read", "FindFunction", "FindCallers", "FindImports"]
SCANNER_SKILL_REFS = ["references/sink-patterns.md"]

# Tuning (see plan P1-4):
#   - Smaller batches (12) → lower chance of a single no_json_found wiping out
#     many files' coverage; higher chance LLM fits everything in one response.
#   - Higher turn budget (60) → Read/Grep over 10–15 files comfortably.
DEFAULT_SCANNER_BATCH_SIZE = 12
# B3: 60 turns left LLMs room to meander; 40 is still plenty for a 12-file
# batch (Read×12 + targeted Grep/Find ≈ 20-30 tool calls worst case) and
# tightens the ceiling on Scanner cost when a batch starts spinning.
DEFAULT_SCANNER_MAX_TURNS = 40


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
) -> ScannerBatchResult:
    """Scan in batches to stay under context limits. Returns ScannerBatchResult.

    Batches are built by directory clustering (see scope.cluster_by_directory)
    so same-module files share a Scanner window — preserves cross-file signal
    that a pure slice-every-N strategy would lose.

    Raises RuntimeError if every batch failed with an LLM error so users don't
    mistake an infra failure for a clean codebase.
    """
    if not files:
        return ScannerBatchResult()

    batches = cluster_by_directory(files, target_batch_size=batch_size)
    all_candidates: list[dict] = []
    errors: list[str] = []
    agg_usage: dict[str, int] = {
        "input_tokens": 0, "output_tokens": 0,
        "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0,
    }

    def _absorb(result: AgentResult) -> None:
        if result.usage:
            for k in agg_usage:
                agg_usage[k] += result.usage.get(k, 0)

    def _ingest(batch_idx: int, result: AgentResult) -> int:
        """Merge parsed candidates from a batch; return count added."""
        if not (result.parsed and isinstance(result.parsed.get("candidates"), list)):
            return 0
        added = 0
        for idx, cand in enumerate(result.parsed["candidates"]):
            cand["id"] = f"b{batch_idx}_{cand.get('id', idx)}"
            all_candidates.append(cand)
            added += 1
        return added

    # Retryable outcomes: the LLM either produced nothing parseable
    # (``no_json_found`` / ``max_turns_exceeded``) or an empty candidate list.
    # These are the main silent-FN source (run 24874431356 lost ~24 files this
    # way). Transient llm_errors are also worth one more try.
    RETRYABLE = {"no_json_found", "max_turns_exceeded"}

    for batch_idx, batch in enumerate(batches):
        result = await run_scanner(repo, batch, max_turns=max_turns)
        _absorb(result)
        added = _ingest(batch_idx, result)

        needs_retry = False
        reason = ""
        if result.error in RETRYABLE:
            needs_retry = True
            reason = result.error or ""
        elif result.error and result.error.startswith("llm_error:"):
            needs_retry = True
            reason = result.error

        if needs_retry:
            print(
                f"  [scanner batch {batch_idx}] {reason}; retrying once "
                f"({len(batch)} files)"
            )
            retry = await run_scanner(repo, batch, max_turns=max_turns)
            _absorb(retry)
            retry_added = _ingest(batch_idx, retry)
            if retry.error and retry.error not in ("no_json_found",):
                errors.append(retry.error)
                print(f"  [scanner batch {batch_idx} retry] error: {retry.error}")
            elif retry.error == "no_json_found":
                # Still nothing — record so the hard-fail gate sees it.
                errors.append(retry.error)
                print(f"  [scanner batch {batch_idx} retry] still no_json_found; giving up on this batch")
            else:
                print(f"  [scanner batch {batch_idx} retry] recovered +{retry_added} candidate(s)")
        elif result.error:
            errors.append(result.error)
            print(f"  [scanner batch {batch_idx}] error: {result.error}")
        _ = added  # silence unused

    if errors and len(errors) == len(batches) and not all_candidates:
        raise RuntimeError(
            f"Scanner failed on all {len(batches)} batch(es). "
            f"First error: {errors[0]}"
        )

    # A2: dedup by (sink_type, file, line). Same Scanner batch often emits the
    # same file:line multiple times with slightly different snippets (common
    # with mimo/gpt class models on Java); keeping only the longest-snippet
    # representative cuts Validator work by 30-50% without losing signal.
    # If ``line`` is missing we fall back to treating the snippet as the key
    # so snippet-differentiated candidates are still preserved.
    deduped: dict[tuple, dict] = {}
    for cand in all_candidates:
        sink = cand.get("sink_type", "other")
        file = str(cand.get("file", ""))
        line = cand.get("line")
        if line is None:
            key = (sink, file, None, str(cand.get("snippet", ""))[:120])
        else:
            key = (sink, file, int(line) if str(line).isdigit() else line)
        prev = deduped.get(key)
        if prev is None:
            deduped[key] = cand
            continue
        # Keep the one with the richer snippet so Validator has more to go on.
        if len(str(cand.get("snippet", ""))) > len(str(prev.get("snippet", ""))):
            deduped[key] = cand

    collapsed = list(deduped.values())
    if len(collapsed) < len(all_candidates):
        print(
            f"  [scanner] deduped {len(all_candidates)} → {len(collapsed)} "
            f"candidate(s) by (sink_type, file, line)"
        )
    return ScannerBatchResult(
        candidates=collapsed,
        usage=agg_usage,
        calls=len(batches),
        batches=len(batches),
    )
