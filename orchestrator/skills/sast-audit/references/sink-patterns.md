# 常见危险 Sink 模式速查

## 如何使用本文档

**本文档是启发式清单，不是封闭集合。**

每个类别分为四层：

1. **核心概念** —— 什么让它危险（判定原理）
2. **危险信号（非穷举）** —— Phase 1 广撒网用的 grep 起手式
3. **判定原则** —— 遇到未列出的模式如何泛化判断
4. **安全反例** —— 看到这些可以快速排除

**关键原则**：
- 例子用于**启动扫描思路**，不是用于"只要不匹配就排除"
- 遇到未列出但符合"核心概念"的模式，**同样视为候选**，进入 Phase 2 验证
- 最终判定以 `SKILL.md` 的 5 阶段流程为准，本文档只覆盖 Phase 1

---

## SQL 注入 / NoSQL 注入

### 核心概念

任何将**未参数化的用户输入**拼接进查询字符串（SQL/HQL/JPQL/MongoDB 表达式）的代码都是 sink。

判定时回答两个问题：
1. 查询字符串是否由**字符串拼接、格式化、模板插值**构造？
2. 拼入的变量是否**可被用户输入污染**？

两个都是 → 候选 sink。

### 危险信号（非穷举）

**Java / JVM**
- `createNativeQuery(...)`、`createQuery(...)` + 字符串 `+` 或 `String.format`
- `Statement`（而非 `PreparedStatement`）、`executeQuery`、`executeUpdate` 带拼接
- MyBatis XML / 注解中的 `${...}`（而非 `#{...}`）
- Spring Data `@Query(nativeQuery = true, value = "..." + var)`
- Hibernate `Session.createSQLQuery`、HQL 拼接
- `NamedParameterJdbcTemplate` 被误用为拼接场景

**Node.js**
- 模板字符串：`` db.query(`SELECT ... ${x}`) ``
- `knex.raw(sql + input)`、Sequelize `sequelize.query(sql+input)`
- TypeORM `query()` / `createQueryBuilder().where("col = '"+x+"'")`
- Mongo：`$where: "this.name == '" + x + "'"`、`db.eval`、`db.collection.find({$where: userInput})`

**Python**
- f-string / `%` / `.format()` + `cursor.execute`
- Django：`.raw()`、`.extra(where=[...])`、`RawSQL`
- SQLAlchemy：`text("..." + x)`、`session.execute(text(...))` 带拼接
- Peewee：`Model.raw(...)`、`fn.*` 原始片段
- Mongo：PyMongo `$where` 带拼接

**PHP / Go / Rust / 其他**
- PHP：`mysql_query`、`mysqli_query`、PDO 不用 `prepare` 而直接拼 `query`
- Go：`db.Query(fmt.Sprintf(...))`、`db.Exec("..." + x)`
- Rust：`sqlx::query(&format!(...))` 而非 `sqlx::query!`（宏版本安全）

### 判定原则

看到以下任一特征都要当作候选，即使 API 不在上述列表中：

- 查询语言关键字（`SELECT`/`INSERT`/`UPDATE`/`DELETE`/`WHERE`/`ORDER BY`）出现在**字符串拼接或模板插值**里
- 变量名暗示 SQL 片段：`orderBy`、`whereClause`、`tableName`、`columnName`、`rawSql`
- ORM 提供的"逃生通道"：带 `raw`、`native`、`exec`、`unsafe` 字样的 API
- 动态表名、动态列名、动态排序方向 —— 这些**无法用参数化修复**，必须白名单

### 安全反例（可快速排除）

- 占位符：`?`、`$1`、`:name`、`#{...}`、`@Param`
- ORM 的类型化 API：Criteria Builder、`findByXxx`、`where(eq(col, val))`、Prisma `where: { id }`
- 宏版本：Rust `sqlx::query!`（编译期检查）、Elixir `Ecto.Query`
- SQL 拼的是**常量**（枚举、白名单查表结果）

---

## 命令注入 / OS 命令执行

### 核心概念

任何将用户输入传给 **shell 解释器**（而非直接 execve）的调用都是 sink。
本质是：输入是否可能被 shell 解析为元字符（`;`、`|`、`&`、`` ` ``、`$()`、`\n`）。

### 危险信号（非穷举）

**Java**：`Runtime.exec(String)`（单字符串版本会过 shell）、`ProcessBuilder("sh","-c", cmd+x)`
**Node.js**：`child_process.exec`、`execSync`、`spawn("sh",["-c",...])`
**Python**：`os.system`、`os.popen`、`subprocess.run(..., shell=True)`、`subprocess.call(shell=True)`、`commands.getoutput`
**Go**：`exec.Command("sh", "-c", x)`、`exec.Command("bash", "-c", x)`
**Ruby**：反引号 `` `cmd #{x}` ``、`system(str)`（单字符串）、`%x{}`、`Kernel#eval`
**PHP**：`exec`、`shell_exec`、`system`、`passthru`、`` ` ` `` 反引号、`popen`

### 判定原则

- 出现 **shell 元字符解析环境**（`sh -c`、`bash -c`、`cmd /c`、Windows `ShellExecute`）+ 用户输入 → 危险
- **即使看似"只是文件名"**，如果传给 shell 形式的 exec，`$(...)` 或 `;rm -rf` 仍会被解析
- 检查是否有**间接注入**：输入写入脚本文件后执行、输入作为环境变量被 shell 脚本使用

### 安全反例

- argv 数组形式（不过 shell）：`execFile("ls",[dir])`、`subprocess.run(["ls",dir])`、`exec.Command("ls",dir)`
- Java `Runtime.exec(String[])`（数组版本）
- 明确白名单 / 正则校验后再传

---

## XSS（跨站脚本）

### 核心概念

任何将用户输入**作为 HTML/JS/CSS 注入到浏览器 DOM**、且未经过上下文正确的转义的代码。
关键是**输出上下文**：HTML body、属性、`<script>` 内、URL、CSS —— 每种需要不同的转义。

### 危险信号（非穷举）

**React / Vue / Angular / Svelte**
- React：`dangerouslySetInnerHTML={{__html: x}}`
- Vue：`v-html="x"`、`{{{ x }}}`（旧版）
- Angular：`[innerHTML]`、`bypassSecurityTrust*`
- Svelte：`{@html x}`

**原生 DOM**
- `element.innerHTML = x`、`outerHTML`、`insertAdjacentHTML`
- `document.write`、`document.writeln`
- `eval`、`new Function`、`setTimeout("str")`、`setInterval("str")`
- `<a href={x}>` 其中 x 可能是 `javascript:...`
- `element.setAttribute("onclick", x)`、`location = x`

**jQuery / 老库**
- `$(x)`（选择器中传入 HTML）、`.html(x)`、`.append(x)`、`.prepend(x)`、`.after(x)`、`.before(x)`、`.replaceWith(x)`

**模板引擎**
- Handlebars：`{{{ x }}}`（三花括号绕过转义）
- Jinja2 / Twig：`{{ x | safe }}`、`{% autoescape false %}`
- EJS：`<%- x %>`（而非 `<%= x %>`）
- Thymeleaf：`th:utext`（而非 `th:text`）
- Mustache：`{{{ x }}}`

**后端直接输出 HTML**
- JSP：`<%= x %>`（不转义）、`out.print(x)`
- PHP：`echo $x`、`<?= $x ?>` 未调用 `htmlspecialchars`

### 判定原则

- **"字符串 → 浏览器解释"** 的任何路径都需要转义 —— 不限于 HTML，包括：
  - 属性内（尤其是 `href`、`src`、`on*` 事件属性）
  - `<script>` 内联
  - CSS `url()`、`expression()`
  - `postMessage` 接收端的 `eval` 风格处理
- **Stored XSS** 更隐蔽：输入在 A 接口存，在 B 接口渲染 —— 两端都要查
- **DOM XSS**：纯前端的 `location.hash` / `URLSearchParams` → sink，后端无感

### 安全反例

- React `{x}`（默认转义）、Vue `{{ x }}`、Angular `{{ x }}`
- 模板引擎默认双花括号 `{{ x }}` 的自动 HTML 转义
- 显式调用 `escapeHtml` / `encodeURIComponent` / `DOMPurify.sanitize`
- CSP 严格配置（`script-src` 无 `unsafe-inline`）可减轻影响

---

## 路径遍历 / 任意文件读写

### 核心概念

任何用**用户输入构造文件路径**且**未将最终路径限制在预期目录内**的代码。
关键是 `..`、绝对路径、符号链接、URL 编码 `%2e%2e` 是否被正规化后重新校验。

### 危险信号（非穷举）

**Java**：`new File(userPath)`、`FileInputStream`、`FileOutputStream`、`Files.readAllBytes`、`Paths.get(base + user)`、`ZipEntry.getName()`（Zip Slip）
**Node.js**：`fs.readFile/writeFile/createReadStream`、`path.join(base, user)` 未做 startsWith 校验、`tar`/`zip` 解压
**Python**：`open(user)`、`os.path.join(base, user)` 未规范化、`zipfile.extract`（Zip Slip）、`tarfile.extractall`
**Go**：`os.Open`、`filepath.Join` 未 `filepath.Clean` + `strings.HasPrefix` 校验
**通用**：上传文件时用原始 `filename`、下载接口 `?file=` 参数

### 判定原则

- **任何拼接基础目录 + 用户输入**的路径构造，若后续没有"规范化并验证 startsWith(basedir)"，都是 sink
- **Zip/Tar 解压**天然是路径遍历温床（entry name 就是攻击面）
- Windows 额外注意：`\`、`..\..\`、`C:`、UNC 路径 `\\server\share`
- **符号链接攻击**：即使路径合法，目标文件可能是符号链接指向 `/etc/passwd`

### 安全反例

- 规范化后 startsWith 校验：`Paths.get(base,user).normalize().startsWith(base)`
- 白名单文件名（UUID 查表 → 真实路径）
- 使用 chroot / 容器隔离

---

## SSRF（服务端请求伪造）

### 核心概念

服务端**用用户提供的 URL 发起网络请求**，且未限制目标地址范围。
攻击面：云元数据（`169.254.169.254`）、内网服务、`file://` 本地文件、`gopher://` 协议走私。

### 危险信号（非穷举）

**Java**：`new URL(x).openConnection()`、`RestTemplate.getForObject(x)`、`WebClient.get().uri(x)`、`HttpClient.send(...URI.create(x)...)`、`OkHttpClient`、Apache `HttpClient`、`ImageIO.read(URL)`、XML 解析器加载外部 DTD
**Node.js**：`fetch(x)`、`axios.get(x)`、`request(x)`、`http.get(x)`、`got(x)`、`node-fetch`
**Python**：`requests.get(x)`、`urllib.request.urlopen(x)`、`httpx.get(x)`、`aiohttp.get(x)`、`PIL.Image.open(URL)`
**其他**：Webhook 接收方、PDF 生成器渲染远程资源、Markdown 渲染器加载远程图片、OAuth redirect URI 未校验

### 判定原则

- 任何 **"我方服务器代替客户端发起请求"** 的功能都是 SSRF 候选
- 间接 SSRF：用户传 URL 给第三方服务（如解析器、截图服务），第三方再请求 —— 仍可能利用
- 未过滤的协议：`file://`、`gopher://`、`dict://`、`ftp://`、`jar:`、`netdoc:`
- 未过滤的 IP：`127.0.0.1`、`localhost`、`0.0.0.0`、`::1`、`10.*`、`172.16-31.*`、`192.168.*`、`169.254.*`、IPv6 映射的内网、DNS rebinding

### 安全反例

- 白名单域名 / IP
- 解析 DNS 后检查目标 IP 不在内网段（要防 DNS rebinding：解析一次就用解析结果连接）
- 禁用重定向或对重定向目标再校验
- 禁用非 HTTP(S) 协议

---

## 反序列化 / 对象注入

### 核心概念

将**不可信字节流**还原为运行时对象，若目标语言的反序列化机制允许"带副作用的构造"，攻击者可控对象图 → RCE。

### 危险信号（非穷举）

**Java**：`ObjectInputStream.readObject()`、`XMLDecoder`、Jackson `enableDefaultTyping` / `@JsonTypeInfo`、Fastjson `autoType=true`、XStream 默认配置、SnakeYAML `Yaml().load()`（非 SafeConstructor）
**Python**：`pickle.loads`、`cPickle`、`yaml.load`（无 `SafeLoader`）、`dill`、`shelve`
**PHP**：`unserialize($_GET[...])`、Phar 反序列化（`file_exists("phar://...")`）
**Ruby**：`Marshal.load`、YAML `psych` 不安全模式
**.NET**：`BinaryFormatter`、`NetDataContractSerializer`、`SoapFormatter`、`LosFormatter`
**Node.js**：`node-serialize`、`serialize-javascript` 误用、`eval` 处理 JSON

### 判定原则

- **任何"二进制/文本 → 对象"且保留类型信息的反序列化**都高危
- 纯数据格式（标准 JSON、Protobuf）**通常安全**，但要看反序列化库是否扩展了类型支持（如 Jackson 开启 DefaultTyping 后 JSON 也变危险）
- 即使无 RCE，反序列化也可能导致 DoS（资源耗尽、ReDoS）

### 安全反例

- `yaml.safe_load`、Jackson 默认配置、Fastjson `safeMode`
- 只用字段白名单的 DTO + 标准 JSON
- 签名校验后再反序列化（HMAC）

---

## 认证 / 授权绕过

### 核心概念

**访问控制逻辑存在漏洞**：未认证的请求到达本应认证的端点，或低权限用户访问高权限资源。

### 危险信号（非穷举）

- Spring Security：`permitAll()`、`antMatchers("/**")` 过宽、过滤器顺序错误
- Sa-Token / Shiro：`excludePaths`、`anon` 路径包含敏感端点
- 自定义过滤器：`ignoreAuth` 列表、路径匹配用 `startsWith` 导致 `/admin/../public` 绕过
- JWT：`alg: none` 接受、密钥硬编码、不校验 `exp` / `iss`
- 水平越权：接口用 `request.getUser()` 但操作目标由 URL 参数 `?id=` 指定，未校验归属
- 垂直越权：前端隐藏按钮但后端无角色校验
- 路径规范化不一致：`/Admin/x`（大小写）、`/admin/./x`、URL 编码 `%2f`

### 判定原则

- **认证 ≠ 授权**：通过认证只是"你是谁"，还要"你能做什么"
- **每个敏感操作都必须有服务端检查**，前端校验仅 UX
- **排除路径清单**是高危配置：每条都要审

### 安全反例

- 方法级注解：`@PreAuthorize("hasRole('ADMIN') and #id == principal.id")`
- 资源级检查：查询 `SELECT ... WHERE id=? AND owner=?`（把所有权下沉到 SQL）

---

## 硬编码密钥 / Secrets

### 核心概念

源码 / 配置 / 构建产物中**包含可独立使用的凭证**。

### 危险信号（非穷举）

```
AKIA[0-9A-Z]{16}                 AWS Access Key
ghp_[A-Za-z0-9]{36}              GitHub Personal Token
gho_/ghs_/ghu_                   GitHub OAuth/Server/User Token
sk-[A-Za-z0-9]{20,}              OpenAI / Anthropic API Key
xox[baprs]-[0-9A-Za-z-]{10,}     Slack Token
-----BEGIN (RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----
password\s*=\s*["'][^"']+["']
secret\s*=\s*["'][^"']+["']
api[_-]?key\s*=\s*["'][^"']+["']
```

### 判定原则

- 不只看源码，还要检查：`.env` 被提交、Docker ENV、K8s ConfigMap（非 Secret）、前端 bundle（浏览器可见所有"前端 env"）
- 前端打包产物内的 API Key 必为公开凭证（所有用户可提取）
- Git 历史中的 secret 即使已删除，仍需**撤销并轮换**

### 安全反例

- 从环境变量读取、从 Secret Manager 取
- `.env` 在 `.gitignore`
- 前端调用 Key：应是**带 Referer/域名限制**的公开 Key，或走后端代理

---

## 弱加密 / 不安全随机

### 核心概念

密码学原语选择错误：过时算法、错误模式、用错随机源。

### 危险信号（非穷举）

- 密码存储：`MD5`、`SHA-1`、`SHA-256`（裸用，无 salt+slow KDF）
- 对称加密模式：`AES/ECB/*`、`DES`、`3DES`、`RC4`、`Blowfish`
- 随机源（用于 token / session / reset link）：`java.util.Random`、`Math.random()`、`rand()`、Python `random` 模块
- 非恒时比较：`==` / `equals` 比较 HMAC / token（应用 `MessageDigest.isEqual` / `hmac.compare_digest`）
- JWT：`HS256` 密钥过短、`none` 算法接受

### 判定原则

- **密码存储**必须用慢 KDF：bcrypt / scrypt / argon2 / PBKDF2（足够迭代次数）
- **安全随机**用 `SecureRandom` / `secrets` 模块 / `crypto.randomBytes`
- **加密**优选 AEAD：AES-GCM、ChaCha20-Poly1305
- 模式：`GCM` / `CBC + HMAC`，**禁用 ECB**

### 安全反例

- bcrypt / argon2 / scrypt 存密码
- `SecureRandom.getInstanceStrong()`
- `AES/GCM/NoPadding`

---

## 敏感信息泄露

### 核心概念

数据**流向不该流向的通道**：日志、异常响应、HTTP 头、URL、缓存。

### 危险信号（非穷举）

- 日志：`log.info("pwd={}",pwd)`、`System.out.println(secret)`、打印整个 request / response body
- 异常响应：`return e.getStackTrace()`、Spring 的 `server.error.include-stacktrace=always`
- HTTP 头：`Server: Apache/2.4.1`、`X-Powered-By`、`X-AspNet-Version`
- URL 查询参数传敏感数据：`?token=xxx`（会进日志 / Referer / 浏览器历史）
- 缓存：敏感数据无 `Cache-Control: no-store`
- 调试接口：`/actuator/*`、`/debug/*`、`/swagger-ui`、`/graphql` 自省

### 判定原则

- **任何经过用户不可信网络/存储/日志系统的数据**都要问：这里该不该有敏感字段？
- PII / 凭证 / 内部拓扑信息 / 堆栈 —— 默认**不**输出，例外才输出

---

## XXE / XML 外部实体

### 核心概念

XML 解析器默认允许外部实体引用 → 可读本地文件、触发 SSRF。

### 危险信号（非穷举）

- Java：`DocumentBuilderFactory`、`SAXParserFactory`、`XMLInputFactory`、`TransformerFactory`、`SchemaFactory`、`Unmarshaller` 未禁用 DTD
- Python：`xml.etree.ElementTree`（老版本）、`lxml.etree.parse` 未设 `resolve_entities=False`
- .NET：`XmlDocument`、`XmlTextReader` 未设 `XmlResolver = null`
- PHP：`libxml_disable_entity_loader(false)`、`simplexml_load_*` 加 `LIBXML_NOENT`

### 判定原则

- 任何接收 XML 的端点（SOAP、SAML、OOXML 文档、XML API）默认高风险
- 即使只做 `validate`，解析阶段就会触发外部实体
- SVG 是 XML —— 上传 SVG 然后服务端用 XML 解析器处理 = XXE

### 安全反例

- 显式禁用：`disallow-doctype-decl=true`、`external-general-entities=false`
- 改用 JSON 如业务允许

---

## 开放重定向

### 核心概念

用户提供的 URL 直接用于 `redirect` / `Location` 头，攻击者构造钓鱼链接。

### 危险信号（非穷举）

- `response.sendRedirect(request.getParameter("url"))`
- `res.redirect(req.query.next)`
- OAuth 回调：`redirect_uri` 不在白名单
- 登录后 `?returnTo=` / `?next=` 未校验

### 判定原则

- 任何 301/302 响应中的 `Location` 值若来自用户输入都是候选
- 包括协议相对 URL `//evil.com`、反斜杠绕过 `/\evil.com`、URL 编码

### 安全反例

- 白名单域名
- 只允许站内相对路径（严格校验 `startsWith("/")` 且不是 `//`）

---

## 竞态条件 / TOCTOU

### 核心概念

检查（time-of-check）和使用（time-of-use）之间存在时间窗口，攻击者在窗口内改变状态。

### 危险信号（非穷举）

- `if (file.exists() && canRead) { read(file) }` —— 中间被换成符号链接
- 余额检查与扣款分离：`if (balance >= x) balance -= x` 未加锁 / 事务
- 唯一性检查：先 `SELECT` 再 `INSERT` 未加唯一约束
- 限流：先读计数再加，无原子操作

### 判定原则

- 涉及**金钱、库存、邀请码、兑换券、限频**的业务逻辑 —— 必须审并发
- 文件操作尽量用原子 API（`openat`、`renameat`）

---

## CSRF

### 核心概念

浏览器自动携带 Cookie，攻击站点发起跨站请求 → 以受害者身份执行操作。

### 危险信号（非穷举）

- Spring Security：`http.csrf().disable()` 且使用 Cookie 认证
- Flask / Django 关闭 CSRF 中间件
- API 用 Cookie 认证但无 CSRF token 且无 `SameSite` 配置

### 判定原则

- **Cookie 认证 + 状态变更操作**必须有 CSRF 防护（Token / SameSite=Lax/Strict / Origin 校验）
- **Bearer Token（Header）认证**天然免疫 CSRF
- 同源 SPA + `SameSite=Lax` 可覆盖多数场景

---

## SSTI（服务端模板注入）

### 核心概念

用户输入被当作**模板代码**而非模板数据渲染，模板引擎暴露运行时对象 → RCE。

### 危险信号（非穷举）

- Python：`Template(user_input).render()`（Jinja2）、`Template(user).substitute`、Mako
- Java：`freemarker.Template` 动态加载用户字符串、Velocity、Thymeleaf 表达式注入
- Node.js：`pug.render(user)`、`handlebars.compile(user)`、EJS 动态编译
- Ruby：ERB `ERB.new(user).result`
- Go：`text/template` / `html/template` 的 `Parse(user)`

### 判定原则

- **模板字符串来自用户**（而不是模板中的变量值来自用户）= 高危
- 区分"用户数据填入模板占位符"（通常安全）vs"用户字符串作为模板被编译"（危险）

---

## 业务逻辑类（IDOR / 越权 / 批量赋值）

### 核心概念

框架语法层面无"漏洞"，但业务规则失效。

### 危险信号（非穷举）

- IDOR：`GET /api/order/{id}` 未校验订单归属
- 批量赋值：`@RequestBody User user` 允许前端传 `isAdmin=true`、Rails `params.permit!`、Django `ModelForm` 无 `fields` 白名单
- 状态机跳跃：订单状态可从 `created` 直接改 `paid` 绕过支付
- 价格篡改：结算用前端传的 `price` 而非服务端查询
- 优惠券 / 积分：无并发控制导致重复使用

### 判定原则

- **任何与资源所有权相关的操作**：服务端必须校验当前用户对资源的权限
- **任何与金钱相关的计算**：服务端重新计算，不信任前端
- **DTO 白名单**而非黑名单：只接受必要字段

---

## 使用建议

- **Phase 1**：用"危险信号"做广撒网 grep，找到候选点
- **遇到未列出的模式但符合"核心概念"和"判定原则"**：同样进入候选集
- **Phase 2-5**：严格按 `SKILL.md` 流程验证，不要因为"在列表里"就直接判定漏洞，也不要因为"不在列表里"就排除

**本文档的目的是启发，不是替代思考。**
