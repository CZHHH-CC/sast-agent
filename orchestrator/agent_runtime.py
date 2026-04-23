"""Provider-agnostic agent runtime.

Runs a single agent (scanner / validator / fixer / reviewer) as a
tool-use loop against any LLMClient. The loop:

    system + user → client.complete() → if tool_calls: execute tools, append
    tool_result, call again → else: stop. Parse final text for JSON block.

Everything the agent sees is filtered through our own tool executors
(orchestrator.tools), so we control which files it can touch and stay
independent of any vendor SDK's tool layer.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .llm import LLMClient, Message, StopReason, ToolCall, ToolResult, build_client
from .tools import ToolRegistry, build_default_readonly_registry


AGENTS_DIR = Path(__file__).parent / "agents"
SKILL_ROOT = Path(__file__).parent / "skills" / "sast-audit"


@dataclass
class AgentResult:
    raw_text: str
    parsed: dict[str, Any] | None
    error: str | None = None
    turns: int = 0
    usage: dict[str, int] | None = None


def _load_prompt(name: str) -> str:
    return (AGENTS_DIR / f"{name}_prompt.md").read_text(encoding="utf-8")


def _compose_system_prompt(role: str, skill_refs: list[str]) -> str:
    parts = [_load_prompt(role)]
    for ref in skill_refs:
        ref_path = SKILL_ROOT / ref
        if ref_path.exists():
            parts.append(
                f"\n\n---\n# Reference: {ref}\n\n{ref_path.read_text(encoding='utf-8')}"
            )
    return "\n".join(parts)


_JSON_BLOCK_RE = re.compile(r"```json\s*(.*?)\s*```", re.DOTALL)


def _extract_json(text: str) -> dict[str, Any] | None:
    m = _JSON_BLOCK_RE.search(text)
    candidate = m.group(1) if m else text.strip()
    try:
        return json.loads(candidate)
    except json.JSONDecodeError:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start != -1 and end > start:
            try:
                return json.loads(candidate[start : end + 1])
            except json.JSONDecodeError:
                return None
        return None


async def run_agent(
    *,
    role: str,
    user_prompt: str,
    cwd: Path,
    allowed_tools: list[str] | None = None,
    skill_refs: list[str] | None = None,
    max_turns: int = 25,
    max_tokens: int = 4096,
    client: LLMClient | None = None,
    registry: ToolRegistry | None = None,
) -> AgentResult:
    """Run an agent turn-loop. Provider-agnostic.

    allowed_tools: subset of registry tool names to expose to the agent. If
    None, all registered tools are allowed.
    """
    client = client or build_client()
    registry = registry or build_default_readonly_registry()
    system = _compose_system_prompt(role, skill_refs or [])

    all_tool_defs = registry.tool_defs()
    if allowed_tools is not None:
        whitelist = set(allowed_tools)
        tool_defs = [t for t in all_tool_defs if t.name in whitelist]
    else:
        tool_defs = all_tool_defs

    messages: list[Message] = [Message(role="user", text=user_prompt)]
    final_text = ""
    total_usage = {
        "input_tokens": 0,
        "output_tokens": 0,
        "cache_read_input_tokens": 0,
        "cache_creation_input_tokens": 0,
    }

    # Use the role name as a cache_key hint so same-role calls share a cache
    # partition (OpenAI Automatic Prompt Caching) / stay within a cache lane.
    cache_key = f"sast-agent/{role}"

    for turn in range(1, max_turns + 1):
        try:
            resp = await client.complete(
                system=system,
                messages=messages,
                tools=tool_defs,
                max_tokens=max_tokens,
                cache_key=cache_key,
            )
        except Exception as e:
            return AgentResult(
                raw_text=final_text, parsed=None,
                error=f"llm_error: {type(e).__name__}: {e}",
                turns=turn - 1, usage=total_usage,
            )

        for k in total_usage:
            total_usage[k] += resp.usage.get(k, 0)

        if resp.message.text:
            final_text = resp.message.text  # keep only latest; JSON is in final turn

        messages.append(resp.message)

        if resp.stop_reason == StopReason.TOOL_USE and resp.message.tool_calls:
            tool_results = await _execute_tool_calls(
                resp.message.tool_calls, cwd=cwd, registry=registry, whitelist=allowed_tools,
            )
            messages.append(Message(role="user", tool_results=tool_results))
            continue

        # End of loop
        parsed = _extract_json(final_text)
        return AgentResult(
            raw_text=final_text,
            parsed=parsed,
            error=None if parsed else "no_json_found",
            turns=turn,
            usage=total_usage,
        )

    # max_turns hit
    parsed = _extract_json(final_text)
    return AgentResult(
        raw_text=final_text, parsed=parsed,
        error=None if parsed else "max_turns_exceeded",
        turns=max_turns, usage=total_usage,
    )


async def _execute_tool_calls(
    calls: list[ToolCall],
    *,
    cwd: Path,
    registry: ToolRegistry,
    whitelist: list[str] | None,
) -> list[ToolResult]:
    results: list[ToolResult] = []
    allowed = set(whitelist) if whitelist is not None else None
    for tc in calls:
        if allowed is not None and tc.name not in allowed:
            results.append(ToolResult(
                tool_call_id=tc.id,
                content=f"Tool '{tc.name}' is not in the allowed set for this agent.",
                is_error=True,
            ))
            continue
        out, is_err = await registry.execute(tc.name, cwd, tc.arguments)
        # Read has its own offset/limit pagination; don't double-truncate here.
        # Other tools (Grep/Glob/FindX) can still produce runaway output on
        # misuse, so keep a generous cap with an explicit truncation notice.
        if tc.name != "Read" and len(out) > 60_000:
            out = (
                out[:60_000]
                + f"\n[... truncated {len(out) - 60_000} chars. "
                f"Narrow the pattern/path/glob to see more.]"
            )
        results.append(ToolResult(tool_call_id=tc.id, content=out, is_error=is_err))
    return results
