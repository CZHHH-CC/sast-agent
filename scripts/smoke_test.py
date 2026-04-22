"""Offline smoke test — verifies non-LLM modules + a fake LLM provider loop.

Run: python scripts/smoke_test.py
"""

from __future__ import annotations

import anyio
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from orchestrator.baseline import Baseline
from orchestrator.fingerprint import make_fingerprint
from orchestrator.report import render_markdown
from orchestrator.scope import full_scan_files

from orchestrator.llm.base import (
    LLMClient, LLMResponse, Message, StopReason, ToolCall, ToolDef,
)
from orchestrator.tools import build_default_readonly_registry
from orchestrator.agent_runtime import run_agent


def test_fingerprint_stability() -> None:
    fp1 = make_fingerprint(
        sink_type="sql_injection", file="src/A.java",
        snippet='String sql = "SELECT * FROM u WHERE id = " + x;',
    )
    fp2 = make_fingerprint(
        sink_type="sql_injection", file="src/A.java",
        snippet='String  sql= "SELECT * FROM u WHERE id = " +x ;',
    )
    fp3 = make_fingerprint(
        sink_type="sql_injection", file="src/A.java",
        snippet='String query = "SELECT * FROM u WHERE id = " + y;',
    )
    assert fp1 == fp2 == fp3, (fp1, fp2, fp3)
    fp_diff = make_fingerprint(
        sink_type="command_injection", file="src/A.java",
        snippet='String sql = "SELECT * FROM u WHERE id = " + x;',
    )
    assert fp_diff != fp1
    fp_unsafe = make_fingerprint(
        sink_type="sql_injection", file="a.java",
        snippet="jdbcTemplate.queryForList(sql)",
    )
    fp_safe = make_fingerprint(
        sink_type="sql_injection", file="a.java",
        snippet="jdbcTemplate.queryForList(sql, new Object[]{x})",
    )
    assert fp_unsafe != fp_safe
    print("[OK] fingerprint stability + discrimination")


def test_scope() -> None:
    root = Path(__file__).parent.parent / "testfixtures" / "vulnerable-java"
    files = full_scan_files(root)
    names = {p.name for p in files}
    for must in (
        "SearchController.java", "CommandRunner.java", "SafeUserDao.java",
        "LoginVo.java", "SecurityConfig.java", "EntityManagerUtil.java",
    ):
        assert must in names, f"missing {must} in {names}"
    print(f"[OK] scope enumerated {len(files)} fixture files")


def test_baseline_roundtrip() -> None:
    tmp = Path(tempfile.mkdtemp()) / "b.db"
    bl = Baseline(tmp)
    bl.upsert("fp1", {
        "status": "confirmed", "severity": "CRITICAL", "sink_type": "sql_injection",
        "file": "a.java", "line": 10, "title": "test",
    })
    bl.upsert("fp2", {
        "status": "excluded", "exclusion_category": "dead_code",
        "sink_type": "sql_injection", "file": "b.java", "line": 5,
        "reason": "no callers",
    })
    assert bl.get("fp1")["status"] == "confirmed"
    assert len(bl.all_confirmed()) == 1
    assert len(bl.all_excluded()) == 1
    bl.upsert("fp1", {
        "status": "confirmed", "severity": "HIGH", "sink_type": "sql_injection",
        "file": "a.java", "line": 10, "title": "test",
    })
    assert bl.get("fp1")["payload"]["severity"] == "HIGH"
    print("[OK] baseline round-trip + upsert idempotency")


def test_report_rendering() -> None:
    md = render_markdown(
        repo=Path("testfixtures/vulnerable-java"),
        confirmed=[{
            "severity": "CRITICAL", "title": "SQL injection", "sink_type": "sql_injection",
            "file": "src/SearchController.java", "line": 20,
            "snippet": 'sql = "SELECT" + x',
            "verified_evidence": {"reachability": "permitAll", "data_flow": "direct",
                                  "no_mitigation": "no params", "exploitability": "UNION"},
            "attack_chain": ["a", "b", "c"],
            "reproduction": "curl ...",
            "impact": "db leak",
            "fix_suggestion": "use ?",
            "cvss_hint": 9.8,
        }],
        excluded=[{
            "exclusion_category": "dead_code", "sink_type": "sql_injection",
            "file": "util/EntityManagerUtil.java", "line": 15,
            "reason": "zero callers",
        }],
        mode="full",
        git_ref="deadbee",
    )
    for snippet in (
        "# vulnerable-java 安全代码审计报告", "CRITICAL 漏洞",
        "EntityManagerUtil", "dead_code", "9.8",
    ):
        assert snippet in md, f"report missing: {snippet!r}"
    print(f"[OK] report rendering ({len(md)} chars)")


# ---------- LLM abstraction tests (fake provider) ----------


class FakeProvider(LLMClient):
    """Deterministic scripted provider for testing the agent loop.

    Scripts are tuples of (expected_turn_idx, response_builder). On each
    complete() call, we consume the next script entry.
    """
    provider = "fake"

    def __init__(self, script: list[LLMResponse]) -> None:
        self.script = list(script)
        self.calls: list[dict] = []

    async def complete(self, *, system, messages, tools, max_tokens=4096):
        self.calls.append({
            "n_messages": len(messages),
            "tool_names": [t.name for t in tools],
            "last_role": messages[-1].role if messages else None,
        })
        if not self.script:
            raise RuntimeError("FakeProvider: script exhausted")
        return self.script.pop(0)


async def _fake_agent_run() -> None:
    """Drive the full agent loop: model asks for a Read tool, we execute it
    against a fixture, then model returns a JSON verdict."""
    repo = Path(__file__).parent.parent / "testfixtures" / "vulnerable-java"
    registry = build_default_readonly_registry()

    # Turn 1: model requests a Read
    turn1 = LLMResponse(
        message=Message(
            role="assistant",
            text=None,
            tool_calls=[ToolCall(
                id="t1",
                name="Read",
                arguments={"file_path": "src/SearchController.java", "offset": 1, "limit": 30},
            )],
        ),
        stop_reason=StopReason.TOOL_USE,
    )
    # Turn 2: model returns a JSON verdict
    turn2 = LLMResponse(
        message=Message(
            role="assistant",
            text='```json\n{"status":"confirmed","candidate_id":"c1","severity":"CRITICAL",'
                 '"title":"SQL injection","sink_type":"sql_injection",'
                 '"file":"src/SearchController.java","line":20,"snippet":"",'
                 '"verified_evidence":{"reachability":"ok","data_flow":"ok",'
                 '"no_mitigation":"ok","exploitability":"ok"},'
                 '"attack_chain":["x"],"reproduction":"","impact":"","fix_suggestion":""}\n```',
            tool_calls=[],
        ),
        stop_reason=StopReason.END_TURN,
    )

    fake = FakeProvider([turn1, turn2])
    result = await run_agent(
        role="validator",
        user_prompt="validate c1",
        cwd=repo,
        allowed_tools=["Read"],
        skill_refs=[],
        max_turns=5,
        client=fake,
        registry=registry,
    )
    assert result.parsed is not None, f"no parsed output: {result.error} / {result.raw_text!r}"
    assert result.parsed["status"] == "confirmed"
    assert result.parsed["severity"] == "CRITICAL"
    assert result.turns == 2, result.turns
    assert len(fake.calls) == 2
    # 2nd call should have: user prompt, assistant (tool_use), user (tool_result)
    assert fake.calls[1]["n_messages"] == 3
    print(f"[OK] agent runtime loop (turns={result.turns}, usage={result.usage})")


async def _tools_sandbox() -> None:
    """Tools must refuse paths outside the scan root."""
    repo = Path(__file__).parent.parent / "testfixtures" / "vulnerable-java"
    reg = build_default_readonly_registry()

    # read inside → ok
    out, err = await reg.execute("Read", repo, {"file_path": "src/SearchController.java"})
    assert not err, out
    assert "SearchController" in out or "jdbcTemplate" in out

    # read escape → must error, not leak content
    out, err = await reg.execute("Read", repo, {"file_path": "../../../../etc/passwd"})
    assert err, "escape attempt should fail"
    assert "escapes" in out.lower()

    # glob + grep
    out, err = await reg.execute("Glob", repo, {"pattern": "**/*.java"})
    assert not err
    assert "SearchController.java" in out

    out, err = await reg.execute("Grep", repo, {"pattern": r"Runtime\.getRuntime"})
    assert not err
    assert "CommandRunner.java" in out
    print("[OK] tool sandbox + grep/glob/read")


async def _provider_translation() -> None:
    """Round-trip: a Message list → provider shape → sanity assertions.
    Does NOT hit any network; we only import the adapter classes."""
    from orchestrator.llm.anthropic_client import AnthropicClient
    from orchestrator.llm.openai_client import OpenAIClient

    # construct without API call
    import os
    os.environ.setdefault("ANTHROPIC_API_KEY", "dummy")
    os.environ.setdefault("OPENAI_API_KEY", "dummy")
    ac = AnthropicClient()
    oc = OpenAIClient()

    tools = [ToolDef(name="Read", description="read", input_schema={"type": "object"})]
    msgs = [
        Message(role="user", text="hello"),
        Message(role="assistant", text=None, tool_calls=[
            ToolCall(id="t1", name="Read", arguments={"file_path": "a.java"}),
        ]),
        Message(role="user", tool_results=[
            __import__("orchestrator.llm.base", fromlist=["ToolResult"]).ToolResult(
                tool_call_id="t1", content="file body", is_error=False,
            ),
        ]),
    ]
    # These are private methods but we're testing translation correctness.
    a_msgs = ac._messages_to_anthropic(msgs)
    assert a_msgs[0]["role"] == "user"
    assert a_msgs[1]["role"] == "assistant"
    assert any(b.get("type") == "tool_use" for b in a_msgs[1]["content"])
    assert any(b.get("type") == "tool_result" for b in a_msgs[2]["content"])

    o_msgs = oc._messages_to_openai("sys prompt", msgs)
    assert o_msgs[0]["role"] == "system"
    assert any(m.get("role") == "tool" for m in o_msgs)
    assert any(
        m.get("role") == "assistant" and m.get("tool_calls") for m in o_msgs
    )
    print("[OK] provider translation (Anthropic + OpenAI shapes)")


def test_ui_endpoints() -> None:
    """UI serves list / detail / trends / api_findings off a seeded baseline,
    and enforces read-only DB access."""
    from fastapi.testclient import TestClient
    from orchestrator.ui import create_app

    tmp_repo = Path(tempfile.mkdtemp()) / "repo"
    (tmp_repo / ".sast-agent").mkdir(parents=True)
    bl = Baseline(tmp_repo / ".sast-agent" / "baseline.db")
    bl.upsert("fp-sql", {
        "status": "confirmed", "severity": "CRITICAL", "sink_type": "sql_injection",
        "file": "src/SearchController.java", "line": 20, "title": "SQL injection",
        "snippet": 'sql = "SELECT" + x',
        "verified_evidence": {"reachability": "permitAll", "data_flow": "direct",
                              "no_mitigation": "no params", "exploitability": "UNION"},
        "attack_chain": ["reach endpoint", "send payload", "dump rows"],
        "reproduction": "curl http://host/api/search?q=' UNION SELECT ...",
        "impact": "full DB read",
        "fix_suggestion": "use ? placeholder",
    })
    bl.upsert("fp-dead", {
        "status": "excluded", "exclusion_category": "dead_code",
        "sink_type": "sql_injection", "file": "util/EntityManagerUtil.java",
        "line": 15, "reason": "zero callers",
    })

    app = create_app(tmp_repo)
    client = TestClient(app)

    r = client.get("/healthz")
    assert r.status_code == 200 and r.json()["ok"] is True

    r = client.get("/")
    assert r.status_code == 200
    body = r.text
    assert "SearchController.java" in body
    assert "EntityManagerUtil.java" in body
    assert "CRITICAL" in body

    # HTMX partial swap returns rows fragment only (no <html> wrapper).
    r = client.get("/", headers={"HX-Request": "true"})
    assert r.status_code == 200
    assert "<html" not in r.text.lower()
    assert "SearchController.java" in r.text

    # Filter to CRITICAL confirmed: the dead-code excluded row drops.
    r = client.get("/api/findings", params={"severity": "CRITICAL", "status": "confirmed"})
    payload = r.json()
    assert payload["count"] == 1
    assert payload["findings"][0]["fingerprint"] == "fp-sql"

    # Free-text search hits path.
    r = client.get("/api/findings", params={"q": "EntityManager"})
    assert r.json()["count"] == 1

    # Detail page contains reproduction + attack_chain.
    r = client.get("/finding/fp-sql")
    assert r.status_code == 200
    assert "dump rows" in r.text
    assert "curl http://host/api/search" in r.text

    r = client.get("/finding/does-not-exist")
    assert r.status_code == 404

    r = client.get("/trends")
    assert r.status_code == 200
    assert "sevChart" in r.text

    # Read-only DB invariant: the UI's `_connect` refuses writes.
    import sqlite3 as _sq
    from orchestrator.ui.queries import _connect
    try:
        with _connect(tmp_repo / ".sast-agent" / "baseline.db") as con:
            con.execute(
                "INSERT INTO findings "
                "(fingerprint,sink_type,file,line,severity,status,"
                "exclusion_category,payload_json,first_seen,last_seen,last_llm_check_at) "
                "VALUES ('x','x','x',1,'LOW','confirmed',NULL,'{}',0,0,0)"
            )
        raise AssertionError("expected readonly failure but write succeeded")
    except _sq.OperationalError as e:
        msg = str(e).lower()
        assert "readonly" in msg or "read-only" in msg or "read only" in msg, msg

    print("[OK] UI endpoints + readonly DB enforcement")


async def _fixer_and_reviewer_parse() -> None:
    """Fixer/Reviewer agents parse the expected JSON shape from the FakeProvider."""
    from orchestrator.fixer_pool import fix_all
    from orchestrator.reviewer_client import coerce_verdict

    repo = Path(__file__).parent.parent / "testfixtures" / "vulnerable-java"
    registry = build_default_readonly_registry()

    # Script: Fixer replies immediately with JSON (no tool calls), carrying a
    # toy diff. Pretend it's already read the file.
    fixer_script = [LLMResponse(
        message=Message(
            role="assistant",
            text=(
                '```json\n{'
                '"candidate_id":"c1",'
                '"files_changed":["src/com/example/SearchController.java"],'
                '"fix_pattern":"parameterized_query",'
                '"explanation":"use placeholder",'
                '"diff":"--- a/src/com/example/SearchController.java\\n+++ b/src/com/example/SearchController.java\\n@@ -1,1 +1,1 @@\\n-old\\n+new\\n",'
                '"breaking_change_risk":"low",'
                '"needs_human_review":true}\n```'
            ),
            tool_calls=[],
        ),
        stop_reason=StopReason.END_TURN,
    )]

    # Patch build_client to return our fake for this call by swapping the
    # `client` kwarg path: fix_all goes through run_agent which accepts
    # `client=` — but fix_all doesn't pass one. So we monkeypatch factory.
    # agent_runtime imports build_client at module load time, so patch that
    # binding (and the re-export in orchestrator.llm for good measure).
    from orchestrator import agent_runtime as _ar
    from orchestrator import llm as _llm

    fake = FakeProvider(fixer_script)
    orig_ar, orig_llm = _ar.build_client, _llm.build_client
    _ar.build_client = lambda *a, **kw: fake
    _llm.build_client = lambda *a, **kw: fake
    try:
        finding = {
            "_fingerprint": "fp-demo", "status": "confirmed", "severity": "CRITICAL",
            "sink_type": "sql_injection", "file": "src/SearchController.java",
            "line": 20, "title": "SQL injection", "snippet": "x",
        }
        fixes = await fix_all(repo, [finding], concurrency=1)
    finally:
        _ar.build_client, _llm.build_client = orig_ar, orig_llm

    assert len(fixes) == 1
    assert fixes[0]["fix_pattern"] == "parameterized_query"
    assert "SearchController" in fixes[0]["diff"]
    assert fixes[0]["needs_human_review"] is True

    # Reviewer coerce: approved path
    approved = AgentResultLike(parsed={
        "candidate_id": "c1", "verdict": "approved",
        "original_vuln_eliminated": True, "same_pattern_elsewhere": [],
        "functional_regression_risk": "low", "notes": "ok",
    }, raw_text="", error=None)
    v = coerce_verdict(approved)
    assert v["verdict"] == "approved"

    # Reviewer coerce: parse failure path
    broken = AgentResultLike(parsed=None, raw_text="blah", error="no_json")
    v2 = coerce_verdict(broken)
    assert v2["verdict"] == "error"
    assert "no_json" in v2["reason"]

    print("[OK] fixer parsing + reviewer verdict coercion")


def _github_helpers_offline() -> None:
    """Validate github.py functions parse correctly without touching network."""
    from orchestrator import github as gh_ops

    # PrCreateResult URL parsing
    # We can't invoke gh for real. Directly exercise the string-parsing path by
    # constructing the object and checking the fields we produce elsewhere.
    res = gh_ops.PrCreateResult(url="https://github.com/o/r/pull/42", number=42)
    assert res.number == 42

    # apply_patch on an empty diff should raise GitError
    import tempfile as _t
    tmp = Path(_t.mkdtemp())
    try:
        gh_ops.apply_patch(tmp, "   ")
        raise AssertionError("expected GitError for empty patch")
    except gh_ops.GitError:
        pass
    print("[OK] github helpers (offline contracts)")


# Tiny shim to build an AgentResult-ish object without importing AgentResult
# (keeps this helper below the AgentResult import ordering explicit).
from dataclasses import dataclass as _dc
@_dc
class AgentResultLike:
    parsed: dict | None
    raw_text: str
    error: str | None


def test_fix_pr_body_rendering() -> None:
    """The fix-PR body concatenates finding + fix + verdict into reviewable markdown."""
    from orchestrator.main import _fix_pr_body
    body = _fix_pr_body(
        finding={
            "sink_type": "sql_injection", "severity": "CRITICAL",
            "file": "a.java", "line": 20, "title": "SQLi",
            "reproduction": "curl ...", "impact": "full DB read",
        },
        fix={
            "fix_pattern": "parameterized_query", "breaking_change_risk": "low",
            "explanation": "use placeholder",
        },
        verdict={"verdict": "approved", "original_vuln_eliminated": True, "notes": "ok"},
    )
    for must in ("requires human review", "parameterized_query", "approved", "SQLi", "a.java"):
        assert must in body, f"missing {must!r} in:\n{body}"
    print("[OK] fix PR body rendering")


if __name__ == "__main__":
    test_fingerprint_stability()
    test_scope()
    test_baseline_roundtrip()
    test_report_rendering()
    anyio.run(_tools_sandbox)
    anyio.run(_fake_agent_run)
    anyio.run(_provider_translation)
    test_ui_endpoints()
    anyio.run(_fixer_and_reviewer_parse)
    _github_helpers_offline()
    test_fix_pr_body_rendering()
    print("\nALL SMOKE TESTS PASSED")
