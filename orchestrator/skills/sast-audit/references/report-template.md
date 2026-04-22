# 安全代码审计报告模板

本文档提供 SAST 审计报告的标准格式。好的报告 = **确认列表 + 排除列表 + 可复现步骤**。

---

## 完整模板

```markdown
# [系统名] 安全代码审计报告

**审计范围**: [审计了什么 —— 模块、分支、commit hash]
**审计日期**: [YYYY-MM-DD]
**审计方式**: 静态代码审计（SAST）
**代码版本**: [commit hash 或 tag]
**审计人**: [姓名或团队]

**确认可利用漏洞数**: N（X CRITICAL，Y HIGH，Z MEDIUM）

---

## 执行摘要

[1-2 段文字概述：审计范围、主要发现、最关键的风险、建议的行动优先级]

示例：
> 本次审计覆盖 XX 系统的认证、授权、文件上传、管理后台四个模块。共发现
> **3 个 CRITICAL 漏洞**（均无需认证、可 RCE），**2 个 HIGH 漏洞**
> （需低权限认证），**4 个 MEDIUM 漏洞**。其中 C1 的 SQL 注入可
> 直接拖库，建议立即修复。另排除 15 个初始发现，详见排除列表。

---

## 排除列表

本列表记录在审计过程中被排除的初始发现，证明审计的完整性。

| # | 类别 | 发现 | 位置 | 排除原因 |
|---|------|------|------|---------|
| X1 | 死代码 | 原始 SQL 拼接 | `EntityManagerUtil.java:45` | 全仓库零调用者 |
| X2 | 死代码 | 路径遍历（4 处） | `DownloadUtils.java:23-89` | 无 import，类从未实例化 |
| X3 | 框架缓解 | XSS via TinyMCE | `RichTextEditor.tsx:12` | TinyMCE 内置清理器剥离事件属性 |
| X4 | 无数据流 | innerHTML 注入 | `useMessage.tsx:23` | 错误消息仅来自枚举常量 |
| X5 | 未使用组件 | `dangerouslySetInnerHTML` | `MarkdownViewer.tsx` | 组件定义但无任何 Page 引用 |
| X6 | Swagger 示例 | 硬编码凭证 | `LoginVo.java:15` | `@ApiModelProperty(example="admin")` 是文档元数据 |
| X7 | 前后端断层 | 批量赋值风险 | `POST /user/user/save` | 前端无任何调用 |
| X8 | 设计行为 | 锁屏 `pwd=undefined` | `LockScreen.jsx:15` | 自动锁定设计意图 |

---

## CRITICAL 漏洞

### C1: [漏洞简洁标题]

**类别**: [SQL 注入 / RCE / 认证绕过 / ...]
**CVSS**: [9.8] | **严重度**: CRITICAL
**位置**: `path/to/file.java:123`

**漏洞代码**：
```java
@PostMapping("/api/search")
public List<User> search(@RequestParam String keyword) {
    String sql = "SELECT * FROM users WHERE name LIKE '%" + keyword + "%'";
    return jdbcTemplate.queryForList(sql, User.class);
}
```

**已验证**（Phase 2-5 检查结果）：
- ✅ **可达性**: 端点 `/api/search` 在 `SearchController.java:45` 注册，前端 `SearchPage.tsx:67` 直接调用
- ✅ **数据流**: `keyword` 参数由 HTTP GET 直接传入，无任何清理
- ✅ **无缓解**: `jdbcTemplate.queryForList` 传入拼接字符串，未使用参数化
- ✅ **无认证**: 端点在 `SecurityConfig.java:34` 的 `permitAll()` 白名单中
- ✅ **影响可证**: 通过 Boolean-Based SQL 注入可拖取整库数据

**攻击链**：
```
攻击者（无需认证）
    ↓
GET /api/search?keyword=' UNION SELECT password FROM users --
    ↓
keyword 原样拼入 SQL
    ↓
MySQL 执行 UNION 查询，返回所有用户密码哈希
    ↓
攻击者获得全库凭证
```

**复现步骤**：
```bash
# 1. 验证漏洞存在（时间盲注）
curl "http://target.com/api/search?keyword=x' AND SLEEP(5) -- "
# 响应时间 > 5s 证明存在注入

# 2. 提取数据（UNION 注入）
curl "http://target.com/api/search?keyword=x' UNION SELECT username,password FROM users -- "

# 3. 自动化利用
sqlmap -u "http://target.com/api/search?keyword=x" --dbs --batch
```

**影响**:
- 全库数据泄露（用户、订单、密钥）
- 可能通过 `INTO OUTFILE` 写入 Webshell，升级为 RCE
- 所有用户密码哈希可离线爆破

**修复建议**:
```java
// 使用参数化查询
String sql = "SELECT * FROM users WHERE name LIKE CONCAT('%', ?, '%')";
return jdbcTemplate.queryForList(sql, new Object[]{keyword}, User.class);

// 或使用 JPA Criteria API
```

---

### C2: [下一个 CRITICAL]

[同格式...]

---

## HIGH 漏洞

### H1: [标题]

**类别**: [...]
**CVSS**: [7.5]
**位置**: `...`

**漏洞代码**:
```
[...]
```

**已验证**: [...]
**攻击链**: [...]
**复现**: [...]
**影响**: [...]
**修复建议**: [...]

---

## MEDIUM 漏洞

### M1: [标题]

[同格式但可以更简洁]

---

## 漏洞统计

| 类别 | CRITICAL | HIGH | MEDIUM | 总计 |
|------|----------|------|--------|------|
| SQL 注入 | 1 | 0 | 0 | 1 |
| XSS | 0 | 1 | 2 | 3 |
| 认证绕过 | 2 | 0 | 0 | 2 |
| SSRF | 0 | 1 | 0 | 1 |
| 敏感信息泄露 | 0 | 0 | 2 | 2 |
| **总计** | **3** | **2** | **4** | **9** |

---

## 跨漏洞攻击链场景

某些漏洞单独严重度有限，但**组合利用可达更高影响**。

### 场景 A: SSRF + 内网认证绕过 → RCE

1. 通过 H1（SSRF）访问内网 `http://10.0.0.5:8080/admin`
2. 该端点通过 IP 白名单认证（未使用强认证）
3. 通过 M2（管理接口命令注入）执行任意命令
4. **最终影响**：内网机器 RCE（升级为 CRITICAL）

### 场景 B: 信息泄露 + 权限提升

1. 通过 M3（Swagger 未关闭）获取 API 列表
2. 通过 M4（敏感参数日志）获取其他用户的 Token
3. 利用其他用户 Token 访问 H2 的权限提升接口
4. **最终影响**：普通用户 → 管理员

---

## 修复优先级

| 优先级 | 漏洞 | 建议修复时间 |
|--------|------|------------|
| P0 | C1, C2, C3 | 24-48 小时 |
| P1 | H1, H2 | 1 周 |
| P2 | M1-M4 | 2 周 |

---

## 审计方法论说明

**本报告采用严格的可利用性验证方法：**

1. **广泛扫描**：识别所有潜在危险代码模式
2. **可达性验证**：排除死代码、无数据流、未使用组件
3. **缓解验证**：检查框架/库的内置保护
4. **利用确认**：构建完整攻击链，不仅是代码模式匹配
5. **设计区分**：排除有意的设计行为

**每个漏洞都通过 8 项检查清单**：
- 危险 sink 存在且可达
- 数据流从入口完整追踪
- 代码不是死代码
- 无框架/库缓解
- 端点/函数被实际使用
- 可描述具体攻击链
- 不是有意设计
- 能提供复现步骤

未通过任何一项 → 进入排除列表。

---

## 附录

### A. 审计覆盖范围清单
- [列出审计的目录、文件、模块]

### B. 使用的工具
- 静态分析: [Grep、Semgrep、CodeQL、...]
- 动态验证: [curl、Burp、sqlmap、...]

### C. 未覆盖范围
- [因时间/权限等未审计的部分]

### D. 参考资料
- OWASP Top 10 映射
- CWE 编号
```

---

## 报告质量检查清单

提交报告前自查：

- [ ] 每个 CRITICAL/HIGH 漏洞都有**可执行的复现步骤**（curl/PoC）
- [ ] 每个漏洞都明确标注了 **CVSS 或严重度**
- [ ] 每个漏洞都写了**具体修复代码**，不只是"建议修复"
- [ ] **排除列表**完整，每项有明确的排除原因
- [ ] 排除原因来自 8 种常见误报类别之一
- [ ] 执行摘要 1-2 段，不超过 200 字
- [ ] 跨漏洞攻击链场景（如有）
- [ ] 漏洞统计表格

---

## 三类要避免的报告

### ❌ 反面案例 1: "代码模式堆砌"

> 发现 27 处 `innerHTML`、15 处 `Runtime.exec`、33 处原始 SQL……

**问题**：只列模式，没有可达性和数据流验证。大量误报，读者无法判断哪些真的需要修。

### ❌ 反面案例 2: "假设可利用"

> "这里的路径参数可能被攻击者控制，可能导致路径遍历。"

**问题**：全是"可能"，没有实际追踪数据流。读者不知道是否真的能利用。

### ❌ 反面案例 3: "无复现步骤"

> "认证绕过漏洞：修改 Cookie 可以绕过。"

**问题**：没有具体的请求、具体的 Cookie 值。读者无法验证。

---

## 正面案例特征

✅ 每个漏洞包含：
- 具体的文件和行号
- 完整的漏洞代码片段
- 明确的验证证据（"我检查了 X 发现 Y"）
- 可复制粘贴的复现命令
- 具体的修复代码
- 排除列表证明审计完整性
