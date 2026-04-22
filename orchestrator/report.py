"""Render markdown reports matching sast-audit/references/report-template.md."""

from __future__ import annotations

from collections import Counter
from datetime import date
from pathlib import Path


SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def _kv(label: str, value: str | None) -> str:
    return f"**{label}**: {value or '—'}"


def _sev_bucket(findings: list[dict]) -> dict[str, list[dict]]:
    bucket: dict[str, list[dict]] = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        sev = (f.get("severity") or "MEDIUM").upper()
        bucket.setdefault(sev, []).append(f)
    return bucket


def _render_confirmed(finding: dict, idx: str) -> str:
    ev = finding.get("verified_evidence", {}) or {}
    chain = finding.get("attack_chain", []) or []
    chain_md = "\n".join(f"{i+1}. {step}" for i, step in enumerate(chain)) or "—"
    return f"""### {idx}: {finding.get('title', '未命名漏洞')}

{_kv('类别', finding.get('sink_type'))} | {_kv('严重度', finding.get('severity'))} | {_kv('CVSS', str(finding.get('cvss_hint') or ''))}
{_kv('位置', f"`{finding.get('file')}:{finding.get('line')}`")}

**漏洞代码**：

```
{finding.get('snippet', '').strip()}
```

**已验证**：
- ✅ 可达性：{ev.get('reachability', '—')}
- ✅ 数据流：{ev.get('data_flow', '—')}
- ✅ 无缓解：{ev.get('no_mitigation', '—')}
- ✅ 可利用性：{ev.get('exploitability', '—')}

**攻击链**：

{chain_md}

**复现**：

```bash
{finding.get('reproduction', '# 暂无复现脚本').strip()}
```

**影响**：{finding.get('impact', '—')}

**修复建议**：{finding.get('fix_suggestion', '—')}

---
"""


def _render_exclusion_row(f: dict, n: int) -> str:
    return (
        f"| X{n} | {f.get('exclusion_category', '—')} | {f.get('sink_type', '—')} "
        f"| `{f.get('file')}:{f.get('line')}` | {f.get('reason', '—')} |"
    )


def render_markdown(
    *,
    repo: Path,
    confirmed: list[dict],
    excluded: list[dict],
    mode: str,
    git_ref: str | None = None,
) -> str:
    bucket = _sev_bucket(confirmed)
    counts = {k: len(v) for k, v in bucket.items()}
    total = sum(counts.values())

    sink_stats: Counter[str] = Counter()
    for f in confirmed:
        sink_stats[(f.get("sink_type") or "other")] += 1

    sections: list[str] = []

    sections.append(f"""# {repo.name} 安全代码审计报告

{_kv('审计范围', str(repo))}
{_kv('审计日期', date.today().isoformat())}
{_kv('审计方式', '静态代码审计（SAST / 多 Agent 流水线）')}
{_kv('代码版本', git_ref or '—')}
{_kv('扫描模式', mode)}

**确认可利用漏洞数**: {total}（{counts.get('CRITICAL', 0)} CRITICAL，{counts.get('HIGH', 0)} HIGH，{counts.get('MEDIUM', 0)} MEDIUM，{counts.get('LOW', 0)} LOW）
**排除发现数**: {len(excluded)}

---

## 执行摘要

本报告由 sast-agent 多 agent 流水线生成：Scanner 广撒网 → Validator 并行验证（证伪优先）。
共确认 {total} 个漏洞，排除 {len(excluded)} 个初始发现（详见排除列表）。

---

## 排除列表

证明审计完整性。

| # | 类别 | sink 类型 | 位置 | 排除原因 |
|---|------|-----------|------|---------|
""")
    for i, f in enumerate(excluded, 1):
        sections.append(_render_exclusion_row(f, i))
    if not excluded:
        sections.append("| — | — | — | — | （无） |")
    sections.append("\n---\n")

    for sev in SEVERITY_ORDER:
        items = bucket.get(sev) or []
        if not items:
            continue
        sections.append(f"\n## {sev} 漏洞\n")
        for i, f in enumerate(items, 1):
            sections.append(_render_confirmed(f, f"{sev[0]}{i}"))

    sections.append("## 漏洞统计\n")
    sections.append("| sink 类型 | 数量 |")
    sections.append("|-----------|------|")
    for sink, n in sink_stats.most_common():
        sections.append(f"| {sink} | {n} |")
    sections.append(f"| **总计** | **{total}** |")

    sections.append("\n---\n")
    sections.append("## 方法论\n")
    sections.append(
        "本报告由 sast-agent 根据 `sast-audit` skill 的 5 阶段方法论生成："
        "Phase 1 广撒网 → Phase 2 可达性 → Phase 3 缓解 → Phase 4 可利用性 → Phase 5 设计 vs 漏洞。"
        "每个候选由独立 Validator agent 并行验证，未通过任何一个 Phase 即进入排除列表。\n"
    )

    return "\n".join(sections)
