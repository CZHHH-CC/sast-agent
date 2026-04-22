"""Provider-agnostic LLM interface.

Every supported provider (Anthropic, OpenAI-compatible, ...) implements the
same LLMClient contract. The orchestrator only speaks this contract — it
never imports provider SDKs directly.

Design goals:
  - single Message shape that round-trips across providers
  - tool_use / tool_result modeled once, translated in each client
  - deterministic "final JSON" extraction stays in the agent runtime, not here
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Literal


Role = Literal["system", "user", "assistant", "tool"]


class StopReason(str, Enum):
    END_TURN = "end_turn"
    TOOL_USE = "tool_use"
    MAX_TOKENS = "max_tokens"
    STOP_SEQUENCE = "stop_sequence"
    ERROR = "error"


@dataclass
class ToolDef:
    """Tool schema in a provider-agnostic shape.

    input_schema follows JSON Schema. Each provider adapter translates this
    into the provider-specific tool declaration."""
    name: str
    description: str
    input_schema: dict[str, Any]


@dataclass
class ToolCall:
    """A tool invocation requested by the assistant."""
    id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ToolResult:
    """Our response to a tool invocation, threaded back to the assistant."""
    tool_call_id: str
    content: str
    is_error: bool = False


@dataclass
class Message:
    """Conversation message. Content is either plain text OR a list of
    rich blocks (text, tool_use, tool_result) — we keep both for clarity."""
    role: Role
    text: str | None = None
    tool_calls: list[ToolCall] = field(default_factory=list)
    tool_results: list[ToolResult] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not (self.text or self.tool_calls or self.tool_results)


@dataclass
class LLMResponse:
    """One assistant turn. `message` is the assistant message to append to
    the running transcript. `stop_reason` drives the agent loop."""
    message: Message
    stop_reason: StopReason
    usage: dict[str, int] = field(default_factory=dict)


class LLMClient(ABC):
    """Provider-agnostic chat completion with tool use."""

    #: human-readable provider id, e.g. "anthropic" or "openai"
    provider: str = "abstract"

    @abstractmethod
    async def complete(
        self,
        *,
        system: str,
        messages: list[Message],
        tools: list[ToolDef],
        max_tokens: int = 4096,
    ) -> LLMResponse:
        """Run one turn. Must NOT execute tools itself — the runtime does that
        and calls complete() again with the tool_result messages appended."""
        raise NotImplementedError
