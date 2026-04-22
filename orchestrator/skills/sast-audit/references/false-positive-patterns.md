# 误报模式库

本文档是代码审计中最容易误判的场景集合。每次审计前先熟读此文档，可以避免大多数误报。

**核心原则：看起来危险 ≠ 真的可利用。**

---

## 类别 1: 死代码（Dead Code）

### 定义

代码中存在危险 sink，但**整个代码库没有任何调用者**。

### 识别方法

```bash
# 搜索类名、方法名、import 语句
grep -r "EntityManagerUtil" --include="*.java"
grep -r "import.*EntityManagerUtil" --include="*.java"
grep -r "new EntityManagerUtil" --include="*.java"
```

### 真实案例

**案例 A: `EntityManagerUtil`**
- 代码中有 `createNativeQuery("SELECT * FROM " + tableName)` 存在 SQL 注入
- 但 Grep 搜索发现**零调用者**
- **判定**：死代码，排除

**案例 B: `DownloadUtils`**
- 4 个方法都有路径遍历漏洞（`new File(userPath)`）
- 无任何 `import DownloadUtils` 语句
- **判定**：死代码，排除

**案例 C: `MarkdownViewer` 组件**
- React 组件使用 `dangerouslySetInnerHTML` 渲染用户输入
- 组件定义了但**从未在任何 Page 中引用**
- **判定**：未使用组件，排除

### 排除条件

- [ ] 全仓库搜索无任何调用
- [ ] 无 `import` 或 `require` 引用
- [ ] 无路由或配置映射到该方法

---

## 类别 2: 无数据流（No Data Flow）

### 定义

危险 sink 存在，代码可达，但**用户输入无法流到 sink**。

### 真实案例

**案例: `useMessage.tsx` innerHTML 注入**

```tsx
// 表面看危险
export function useMessage() {
  const show = (error: Error) => {
    messageRef.innerHTML = error.message;  // ⚠️ innerHTML
  };
}
```

**追踪数据流：**
1. `error.message` 从哪里来？
2. 发现来自全局异常处理器：
   ```java
   @ControllerAdvice
   public class GlobalExceptionHandler {
       @ExceptionHandler
       public ErrorResponse handle(BusinessException e) {
           return new ErrorResponse(e.getErrorCode().getMessage());  // 枚举的消息
       }
   }
   ```
3. `ErrorCode.getMessage()` 返回的是**枚举常量**或**数据库字段**
4. **从不包含 HTTP 请求参数**

**判定**：排除 —— 用户输入无法到达 `innerHTML`

### 识别方法

- 从 sink 往回追溯数据来源
- 确认数据是否来自**用户可控输入**（HTTP 参数、请求体、Header、Cookie、Query、Path Variable）
- 如果来自枚举、常量、数据库内部字段、后端计算结果 → 无数据流

---

## 类别 3: 框架/库内置缓解

### 定义

代码模式看起来危险，但**库/框架自己处理了保护**。

### 真实案例

**案例 A: TinyMCE 富文本编辑器**

```html
<textarea id="editor">用户输入的富文本</textarea>
<script>
  tinymce.init({
    selector: '#editor',
    plugins: 'code',  // ⚠️ 允许查看/编辑 HTML 源码
  });
</script>
```

**表面分析**：用户可以输入 `<img onerror="alert(1)">`，看似 XSS。

**深入验证**：
- TinyMCE 内置 HTML 清理器会**剥离事件属性**（`onerror`、`onclick` 等）
- 即使通过 `code` 插件输入恶意 HTML，最终渲染时会被清理
- **判定**：库已缓解，排除

**案例 B: Spring JPA 参数化查询**

```java
// 看似字符串拼接
String jpql = "SELECT u FROM User u WHERE u.name = :name";
entityManager.createQuery(jpql).setParameter("name", userInput);
```

- `:name` 是 JPQL 命名参数，不是字符串插值
- `setParameter` 会正确转义
- **判定**：参数化查询，安全

### 识别方法

- 查阅库文档中的"Security"部分
- 查看库源码中的 sanitization 逻辑
- 搜索 Issue 和安全公告
- **不要仅凭字面模式下结论**

---

## 类别 4: 未使用的组件/函数

### 定义

代码定义了危险功能，但**功能从未被调用或渲染**。

### 真实案例

**案例: 未使用的 React 组件**

```tsx
// components/MarkdownViewer.tsx
export function MarkdownViewer({ content }) {
  return <div dangerouslySetInnerHTML={{ __html: marked(content) }} />;
}
```

**搜索引用：**
```bash
grep -r "MarkdownViewer" src/
# 结果：只有定义文件自己，无其他引用
grep -r "import.*MarkdownViewer" src/
# 结果：零
```

**判定**：组件未使用，排除

### 识别方法

- Grep 组件名、函数名
- 检查是否注册到路由
- 检查是否被导入和渲染

---

## 类别 5: Swagger/文档示例

### 定义

代码中的"可疑值"其实是**文档或元数据**，不是运行时值。

### 真实案例

**案例: `LoginVo` 示例凭证**

```java
@Data
public class LoginVo {
    @ApiModelProperty(value = "用户名", example = "admin")
    private String username;
    
    @ApiModelProperty(value = "密码", example = "admin123")
    private String password;
}
```

**表面看**：硬编码凭证！

**深入分析**：
- `example = "admin123"` 是 **Swagger 文档示例**
- 仅用于生成 API 文档时显示
- **不会作为运行时默认值使用**

**判定**：文档元数据，排除

### 识别方法

- 确认可疑值的**实际用途**
- Swagger `@ApiModelProperty(example=)`、`@ApiParam(example=)`
- OpenAPI 规范中的 `example` / `default` 字段
- 测试代码中的测试数据
- README/文档示例

---

## 类别 6: 前后端断层

### 定义

后端存在危险端点，但**前端从未调用**。

### 真实案例

**案例: `saveUserInfoAction` 批量赋值**

```java
@PostMapping("/user/user/save")
public Result save(@RequestBody User user) {
    // ⚠️ 无字段过滤，可能批量赋值（含 isAdmin 字段）
    return userService.save(user);
}
```

**前端搜索：**
```bash
grep -r "user/user/save" frontend/
grep -r "saveUserInfoAction" frontend/
# 结果：零
```

**判定**：
- 从**前端工作流**角度：无利用路径，排除正式报告
- 但需备注：攻击者可**直接构造 API 调用**，仍是风险
- 实际报告中可列为 **LOW / MEDIUM**（而非 HIGH/CRITICAL）

### 识别方法

- 后端端点：搜索前端是否调用
- 前端函数：搜索是否被 Page/Route 使用
- 如果端点存在但前端未使用：评估是否仍有直接调用风险

---

## 类别 7: 设计行为误判

### 定义

有意的设计被误判为漏洞。

### 真实案例

**案例 A: 锁屏 `pwd: undefined`**

```javascript
const [lockPassword, setLockPassword] = useState(undefined);

function unlock(input) {
    if (input === lockPassword) {
        setLocked(false);
    }
}
```

**表面看**：密码是 `undefined`，`"" === undefined` 为 false 但 `undefined === undefined` 为 true？

**深入分析**：
- 这是**自动锁定模式**
- 用户未设置密码 → `lockPassword = undefined` → 任何输入都不匹配 → 永远保持锁定
- **设计意图**：未设密码 = 立即锁屏 + 无法解锁

**判定**：有意设计，排除

**案例 B: Token = `'true'`**

```javascript
localStorage.setItem('loggedIn', 'true');
```

**误判**：Token 就是 `'true'`，可以伪造！

**深入分析**：
- 这是**前端会话标志**，不是认证 Token
- 真正的认证用 HttpOnly Cookie（服务端会话）
- 此标志只用于前端条件渲染（如显示/隐藏菜单）
- 后端会话独立于此标志

**判定**：会话标志，不是加密 Token，排除

### 识别方法

- 问：这个行为有文档说明吗？
- 问：修复它会破坏预期功能吗？
- 问：这是配置选择还是编码错误？

---

## 类别 8: 过度推理（Over-inference）

### 定义

单个事实正确，但组合推理错误。

### 真实案例

**案例: "Token 是字符串 + Header 注释提到 Authorization"**

**推理链**：
1. 前端 Token 存储为 `'true'` 字符串 ✓
2. 后端代码注释提到 `@Header("Authorization")` ✓
3. **推理**：后端用 Header 认证，前端 Token 可伪造，Authorization header 可以绕过认证

**验证**：
- 检查后端实际认证代码
- 发现后端实际用 **Cookie + Session**（不是 Header）
- `@Header` 注释是历史遗留，现在未使用
- **推理错误**：两个事实都对，但组合结论错

**判定**：排除

### 预防方法

- **不要用推理代替验证**
- 每一步都要**代码验证**，不是假设
- 多个线索指向同一结论时，**独立验证每一个线索**

---

## 类别 9: CORS 过度宽松但无凭证

### 定义

```java
response.setHeader("Access-Control-Allow-Origin", "*");
```

**看似危险**：任意域可以跨域请求！

**关键验证**：
- 检查 `Access-Control-Allow-Credentials` 是否为 `true`
- 如果为 `false` 或未设置 → 浏览器**不会发送 Cookie**
- 因此攻击者无法利用受害者的会话
- **判定**：可能 LOW，但非 HIGH

---

## 类别 10: 内网限制

### 定义

端点存在漏洞，但**只在内网访问**。

```java
@PostMapping("/internal/admin/reset")
@PreAuthorize("@internalCheck.isInternal()")
public void reset() { ... }
```

**验证**：
- 检查 `@internalCheck.isInternal()` 的实现
- 如果基于 IP 白名单、VPN、内网网段 → 公网不可达
- 严重程度降低（仍可能是 MEDIUM，但不是 CRITICAL）

---

## 排除清单模板

在报告中列出排除项：

```markdown
## 排除列表

| 类别 | 发现 | 位置 | 排除原因 |
|------|------|------|---------|
| 死代码 | SQL 注入 | `EntityManagerUtil.java:45` | 全仓库零调用 |
| 框架缓解 | XSS via TinyMCE | `RichTextEditor.tsx:12` | TinyMCE 内置清理器剥离事件属性 |
| 无数据流 | innerHTML 注入 | `useMessage.tsx:23` | 错误消息仅来自枚举，不含用户输入 |
| 设计行为 | 锁屏密码 undefined | `LockScreen.jsx:15` | 自动锁定设计，非漏洞 |
| 前后端断层 | 批量赋值 | `/user/user/save` | 前端未调用，直接 API 风险备注 |
```

**排除列表的意义**：证明你做了完整审计，而不是只报简单的。一份好的报告，排除列表和确认列表同样重要。

---

## 决策流程

```
发现危险模式
    ↓
代码可达？（有调用者？）──否──→ 排除（死代码）
    ↓ 是
用户输入能到达 sink？──否──→ 排除（无数据流）
    ↓ 是
有框架缓解？──是──→ 验证缓解有效 ──是──→ 排除（已缓解）
    ↓ 否
前后端实际使用？──否──→ 降级或排除（断层）
    ↓ 是
是有意设计？──是──→ 排除（设计行为）
    ↓ 否
    ✅ 确认为漏洞，进入报告
```
