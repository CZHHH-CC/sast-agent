"""Validator pool: group candidates by file, then run Validator agents in parallel.

Design (P1-5):
  Previously every candidate was independent → Validator saw only the sink,
  lost cross-candidate context, and re-read the same file N times. Now:
    * Candidates sharing the same ``file`` are merged into a single Validator
      call (up to MAX_GROUP_SIZE per group).
    * The Validator looks at the full file once and judges all N candidates
      in one JSON output shape: {"validations": [...]}.
    * Groups are fanned out across ``concurrency`` worker slots.
"""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass, field
from pathlib import Path

from .agent_runtime import AgentResult, run_agent


VALIDATOR_TOOLS = ["Glob", "Grep", "Read", "FindFunction", "FindCallers", "FindImports"]
VALIDATOR_SKILL_REFS = [
    "SKILL.md",
    "references/false-positive-patterns.md",
]

# How many candidates we'll pack into one Validator call. Keep low enough that
# the combined context and the JSON output both fit comfortably.
MAX_GROUP_SIZE = 6
VALIDATOR_MAX_TURNS = 40


@dataclass
class ValidatorBatchResult:
    """Output of validate_all.

    - ``results``: validator JSON outputs safe to persist (confirmed / excluded).
    - ``llm_errors``: calls that never produced any usable output because of an
      LLM/infra failure. These MUST NOT be written to the baseline — otherwise
      a transient 403/402/network blip would mark real vulns as "excluded"
      forever and silently suppress future detections.
    - ``parse_errors``: calls that did get a response from the LLM but we could
      not find valid JSON in it.
    """

    results: list[dict] = field(default_factory=list)
    llm_errors: list[dict] = field(default_factory=list)
    parse_errors: list[dict] = field(default_factory=list)
    # B1: aggregate token usage across every group call in this batch.
    usage: dict[str, int] = field(default_factory=dict)
    calls: int = 0

    @property
    def total_attempted(self) -> int:
        return len(self.results) + len(self.llm_errors) + len(self.parse_errors)


# ---------- grouping ----------


def _group_by_file(candidates: list[dict]) -> list[list[dict]]:
    """Bucket candidates by ``file`` field, then split oversized buckets into
    chunks of at most MAX_GROUP_SIZE."""
    by_file: dict[str, list[dict]] = {}
    for c in candidates:
        key = str(c.get("file") or "__unknown__")
        by_file.setdefault(key, []).append(c)

    groups: list[list[dict]] = []
    for _file, cs in by_file.items():
        for i in range(0, len(cs), MAX_GROUP_SIZE):
            groups.append(cs[i : i + MAX_GROUP_SIZE])
    return groups


# ---------- prompts ----------


def _build_group_prompt(repo: Path, group: list[dict]) -> str:
    """Prompt for a multi-candidate Validator call, all candidates sharing a file."""
    file_ref = group[0].get("file", "?")
    slim = []
    for c in group:
        slim.append({
            "id": c.get("id"),
            "sink_type": c.get("sink_type"),
            "line": c.get("line"),
            "snippet": c.get("snippet"),
            "reason_hint": c.get("reason_hint") or c.get("reason"),
        })
    cjson = json.dumps(slim, ensure_ascii=False, indent=2)
    return f"""对以下 {len(group)} 个候选（均位于同一文件 `{file_ref}`）执行 SAST Phase 2-5 验证。

仓库根目录: {repo}

候选列表:
```json
{cjson}
```

要求：
- 把整份文件 Read 一次，建立完整上下文；相关上下游函数可用 FindFunction / FindCallers / FindImports 查询
- 对每个候选独立判定：confirmed 或 excluded（互不影响）
- 证伪优先：尝试所有理由排除它；每一项 verified_evidence 必须有代码查证
- 同一文件内多个候选可能共享 source/sink，允许交叉引用证据，但 status 必须逐个给出

输出 JSON，**必须**严格按以下形状（每个候选一个对象，按 candidate_id 对齐）:
```json
{{
  "validations": [
    {{ "candidate_id": "<id>", "status": "confirmed", ...其余 Validator 字段 }},
    {{ "candidate_id": "<id>", "status": "excluded",  ...其余 Validator 字段 }}
  ]
}}
```
"""


# ---------- execution ----------


async def _validate_group(
    repo: Path, group: list[dict], *, sem: asyncio.Semaphore
) -> AgentResult:
    async with sem:
        return await run_agent(
            role="validator",
            user_prompt=_build_group_prompt(repo, group),
            cwd=repo,
            allowed_tools=VALIDATOR_TOOLS,
            skill_refs=VALIDATOR_SKILL_REFS,
            max_turns=VALIDATOR_MAX_TURNS,
        )


_REQUIRED_DESIGN_INTENT_KEYS = {"override_read_at", "override_set_at", "fail_mode"}

# Secret categories where design_intent is **never** acceptable — even with a
# proper env override, shipping a default is a defense-in-depth issue that
# should surface to humans. See validator_prompt.md "严格要求 (防漏报)".
_NO_DESIGN_INTENT_SINKS = {
    "hardcoded_secret",
    "weak_crypto",
    "auth_bypass",
}


def _enforce_design_intent_rigor(parsed: dict) -> dict:
    """If the Validator used `design_intent` without meeting the evidence
    contract (validator_prompt.md), demote to `over_inference` so the finding
    surfaces for human review instead of silently disappearing from the report.

    Three demotion triggers:
      1. sink_type is in the never-design-intent list (secrets / crypto / auth)
      2. `evidence` is not a dict, or missing any of the three required keys
      3. any of override_read_at / override_set_at lacks a ``:line`` marker
    """
    if parsed.get("status") != "excluded":
        return parsed
    if parsed.get("exclusion_category") != "design_intent":
        return parsed

    def _demote(why: str) -> dict:
        parsed["exclusion_category"] = "over_inference"
        prior = parsed.get("reason") or ""
        parsed["reason"] = (
            f"[auto-demoted from design_intent: {why}] {prior}"
        ).strip()
        return parsed

    sink = str(parsed.get("sink_type") or "").lower()
    if sink in _NO_DESIGN_INTENT_SINKS:
        return _demote(f"sink_type={sink!r} is never a design_intent exclusion")

    evidence = parsed.get("evidence")
    if not isinstance(evidence, dict):
        return _demote("evidence must be an object with override_read_at / override_set_at / fail_mode")

    missing = _REQUIRED_DESIGN_INTENT_KEYS - set(evidence.keys())
    if missing:
        return _demote(f"missing evidence keys: {sorted(missing)}")

    for key in ("override_read_at", "override_set_at"):
        val = str(evidence.get(key) or "")
        if ":" not in val or not val.strip():
            return _demote(f"evidence.{key} must be 'path:line', got {val!r}")

    return parsed


def _enrich_from_candidate(parsed: dict, cand: dict) -> dict:
    parsed.setdefault("file", cand.get("file"))
    parsed.setdefault("line", cand.get("line"))
    parsed.setdefault("sink_type", cand.get("sink_type"))
    parsed.setdefault("snippet", cand.get("snippet"))
    parsed.setdefault("candidate_id", cand.get("id"))
    _enforce_design_intent_rigor(parsed)
    return parsed


def _error_entry(cand: dict, reason: str, turns: int = 0) -> dict:
    return {
        "candidate_id": cand.get("id"),
        "file": cand.get("file"),
        "line": cand.get("line"),
        "sink_type": cand.get("sink_type"),
        "snippet": cand.get("snippet"),
        "reason": reason,
        "turns": turns,
    }


def _distribute_group_result(
    group: list[dict], res: AgentResult, batch: ValidatorBatchResult
) -> None:
    """Fan a single Validator group response back to per-candidate entries."""
    # Hard infra failure → every candidate in the group is an llm_error.
    if res.error and res.error.startswith("llm_error:"):
        for c in group:
            batch.llm_errors.append(_error_entry(c, res.error, res.turns))
        return

    parsed = res.parsed or {}
    validations = parsed.get("validations")
    # Back-compat: if the LLM returned a single-candidate shape (status field
    # at top level, no validations array), fall through as if group_size == 1.
    if not isinstance(validations, list):
        if "status" in parsed and len(group) == 1:
            batch.results.append(_enrich_from_candidate(parsed, group[0]))
            return
        # Otherwise the whole group is a parse_error; every candidate gets one.
        reason = res.error or "no_validations_field"
        for c in group:
            batch.parse_errors.append(_error_entry(c, reason, res.turns))
        return

    by_id = {str(c.get("id")): c for c in group}
    seen_ids: set[str] = set()
    for v in validations:
        if not isinstance(v, dict):
            continue
        cid = str(v.get("candidate_id"))
        cand = by_id.get(cid)
        if cand is None:
            # Validator emitted an id we didn't ask about; ignore.
            continue
        if "status" not in v:
            batch.parse_errors.append(_error_entry(cand, "missing_status", res.turns))
            seen_ids.add(cid)
            continue
        batch.results.append(_enrich_from_candidate(v, cand))
        seen_ids.add(cid)

    # Anyone the validator silently dropped is a parse error.
    for c in group:
        if str(c.get("id")) not in seen_ids:
            batch.parse_errors.append(
                _error_entry(c, "validator_omitted_candidate", res.turns)
            )


async def validate_all(
    repo: Path, candidates: list[dict], *, concurrency: int = 5
) -> ValidatorBatchResult:
    """Run validators concurrently, grouping candidates by file for cross-finding
    context. See module docstring for the design rationale.
    """
    if not candidates:
        return ValidatorBatchResult()

    groups = _group_by_file(candidates)
    sem = asyncio.Semaphore(concurrency)
    tasks = [_validate_group(repo, g, sem=sem) for g in groups]
    results: list[AgentResult] = await asyncio.gather(*tasks)

    batch = ValidatorBatchResult()
    agg = {"input_tokens": 0, "output_tokens": 0,
           "cache_read_input_tokens": 0, "cache_creation_input_tokens": 0}
    for group, res in zip(groups, results):
        _distribute_group_result(group, res, batch)
        if res.usage:
            for k in agg:
                agg[k] += res.usage.get(k, 0)
    batch.usage = agg
    batch.calls = len(groups)
    return batch
