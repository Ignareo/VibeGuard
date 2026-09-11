# PLAN.md — VibeGuard 二次开发优化计划

> 本文件由调研报告整理而成，供后续开发 session 执行。执行前请先读 `AGENTS.md`（构建/测试约定、架构图、上游既有问题清单）。
>
> 核心需求：**敏感词拦截（不漏脱敏、不漏还原）+ 安全审计（审计本身不泄密、可追溯）**。
>
> 每条任务含：问题、位置（文件:行号）、建议做法、验证方式。行号基于 commit `bb1b252`，若代码已变动以符号搜索为准。

## 执行约定

- 构建验证：`GOPROXY=https://goproxy.cn,direct go build ./... && go vet ./... && go test ./...`，改动文件不得出现在 `gofmt -l cmd internal` 输出中。
- 已知上游既有问题（不要顺手"修"）：`internal/wsproxy/transform_conn.go:117` vet 报错；`internal/admin/admin.go`、`internal/auditdb/*.go` gofmt 未格式化。
- 配置新字段要同步三处：`internal/config/config.go` 默认值 + `cmd/vibeguard/main.go` 两个 init 模板（中英文）。
- UI 文案走 `uiText(lang, zh, en)` 双语。
- Commit 用 Conventional Commits（`feat:`/`fix:`/`docs:`），英文。
- 有测试的包（`internal/proxy`、`internal/secretsources`、`internal/textsafe`、`internal/wsproxy`）改动时补测试；无测试的包不新建测试脚手架。

---

## 第一批：堵漏（最高优先级）

### P1-1 修复 invalid_json 回退导致的全量泄露

- **问题**：整文本脱敏破坏了 JSON 结构时，放弃脱敏、**原样转发全部请求体**，仅留 `Note="invalid_json"`。一条过宽规则即可放大成全量泄露。
- **位置**：`internal/proxy/proxy.go:629-634`
- **做法**：回退策略改为按 match 粒度排除可疑匹配后重试（或仅跳过导致 JSON 非法的匹配项），仍失败则按可配置策略拒绝/告警；将 `invalid_json` 提升为显眼的审计事件（审计 Note + warn 日志）。
- **验证**：构造一个会让整文本替换破坏 JSON 的关键词（如含 `"` 的关键词），确认不再原文整体转发，且审计中有明确记录。`internal/proxy` 有测试，补测试。

### P1-2 补齐结构化 JSON 脱敏的字段覆盖

- **问题**：只处理 `messages`/`input`/`contents` 里的 `text`。**system prompt（`system`/`instructions`/`system_instruction`）、`tool_calls[].function.arguments`、Anthropic `tool_use.input`、`tool_result` 嵌套 content 均不脱敏**——恰是 CLI agent 塞文件内容和密钥的位置。
- **位置**：`internal/promptredact/json.go:91-113`（顶层字段分流）、`json.go:151-266`（消息项处理）
- **做法**：顶层 `system`/`instructions`/`system_instruction` 字符串纳入脱敏；`arguments`（注意它是 JSON 字符串，需二次解析递归或按文本脱敏）、`tool_use.input`、`tool_result.content` 递归处理。参考 OpenAI chat.completions / Responses、Anthropic、Gemini 四家格式。
- **验证**：用四家 API 的真实请求样例（含 tool_calls / tool_result / system）过 `RedactJSONBody`，断言命中字段被替换且 JSON 仍合法。

### P1-3 收敛 `<system-reminder>` 豁免

- **问题**：以 `<system-reminder` 开头的 text part 完全跳过脱敏，而 Claude Code / Kimi Code 用它注入文件内容，其中的密钥原样上行。
- **位置**：`internal/promptredact/json.go:250-252`、`268-277`
- **做法**：移除豁免，或仅豁免无命中时、命中高风险类别（secret 类）时仍脱敏并记审计。豁免的初衷（避免破坏 harness 指令解析）需在注释中说明取舍。
- **验证**：含密钥的 `<system-reminder>` text part 经过脱敏后密钥被替换。

### P1-4 补齐 SSE delta 还原覆盖（漏还原最大来源）

- **问题**：`parseDeltaJSON` 只认 Responses API 顶层 `delta` 和 Anthropic `delta.text`；**OpenAI chat.completions 的 `choices[].delta.content`（DeepSeek/Moonshot/Kimi 等最常见格式）落入"整事件字节级还原"**，跨 chunk 被切断的占位符无法还原。多路输出共用一个 `textRestorer` 会串流（代码注释自承认，`reader.go:36-39`）。
- **位置**：`internal/stream/reader.go:594-628`（delta 识别）、`reader.go:139-283`（跨 chunk restorer）、`reader.go:419-428`（整事件 fallback）
- **做法**：新增识别 ① `choices[].delta.content` ② `choices[].delta.tool_calls[].function.arguments` ③ Anthropic `input_json_delta.partial_json`；把单一 restorer 改为按流标识 keyed 的 map（choice index / output_index+content_index / content_block index）。
- **验证**：模拟 chat.completions SSE 流，把一个占位符切成两个 chunk 分别下发，断言还原出原文；两个 choices 交错下发不串流。`internal/stream` 相关测试放合适包内。

### P1-5 审计库防泄密

- **问题**：`redact_log=false` 时敏感**原文明文写入未加密 SQLite**；db 文件权限由 umask 决定（通常 0644）。对比 session WAL 是 AES-GCM + 0600。
- **位置**：`internal/admin/admin.go:189-225`（`adminToDBMatches`）、`internal/auditdb/store_sqlite.go:50-65`（Open）、`:117`（matches 落盘）
- **做法**：① 落盘强制只存 preview（开关拆成"UI 显示原文"与"落盘原文"，后者默认关）；② Open 后 `os.Chmod(path, 0600)`（含 `-wal`/`-shm` 文件）；③（可选中期）matches 列复用 WAL 的 AES-GCM 方案加密。顺带把 log 文件 0644 收紧（`internal/log/log.go:22,55`）。
- **验证**：`redact_log=false` 时打开 audit.db 确认无明文 value；`stat` 确认 0600。

---

## 第二批：防绕过 + 审计可追溯

### P2-1 匹配前归一化防绕过

- **问题**：`textsafe.RedactableSpans` 在零宽字符/控制字符处切段（`internal/textsafe/spans.go:53-93`），敏感词中插一个 `\u200b` 即可绕过；无 NFKC/全角→半角/大小写折叠。
- **做法**：匹配前生成"折叠副本"（去零宽、NFKC、大小写折叠），在折叠文本上匹配再映射回原始偏移。注意保留原文用于还原。
- **验证**：`pass\u200bword`、全角数字手机号、大小写变体能命中；正常文本 offsets 不错位。`internal/textsafe` 有测试，补测试。

### P2-2 元审计（管理员操作留痕）+ 登录防爆破

- **问题**：登录成功/失败、清空审计、改规则/配置**完全不留痕**（`internal/admin/handler.go:92` 仅 debug 级）；登录无速率限制（`internal/admin/api_auth.go:80-117`）。
- **做法**：新增 append-only 元审计流（info 级落盘或独立表），记录登录/清空审计/规则与配置变更；登录加失败计数+延迟/锁定。DELETE `/manager/api/audit`（`api_audit.go:57-71`）本身写一条元审计。
- **验证**：执行上述操作后元审计有记录；连续错误登录被限速。

### P2-3 中文 PII 与规则校验位

- **问题**：身份证无校验位验证（`internal/defaultrules/default.vgrules:35`，18 位数字即命中→误报）；无 19 位借记卡/护照/统一社会信用代码；NER `language:auto` 被硬编码为 `en`（`internal/pii_next/ner/presidio.go:90-92`）。
- **做法**：`.vgrules` 格式扩展校验/置信度语义（如 `:: luhn`、min_score，解析在 `internal/pii_next/rulelist/rulelist.go:181-219`）；默认规则加银行卡 16~19 位（Luhn）、护照、统一社会信用代码；NER 允许 `zh` 并写部署文档。
- **验证**：合法/非法身份证号、Luhn 通过/失败的卡号用例。

### P2-4 规则订阅防投毒

- **问题**：订阅只靠 HTTPS，无签名/钉扎（`internal/rulelists/subscription.go:208-404`）；默认订阅 URL 指向上游 `inkdust2021/vgrules`（`internal/config/config.go:168`），fork 后规则更新权不在本项目手中。
- **做法**：支持 `sha256_pin`（TOFU 钉扎）或 minisign 签名文件校验；把默认订阅迁移到本 fork 控制的仓库。
- **验证**：篡改订阅内容后更新被拒绝并告警。

### P2-5 死代码与静默失败收敛

- **问题**：`patterns.regex`/`builtin` 被主路径忽略（`internal/proxy/proxy.go:1208-1216`），`internal/redact/builtin.go` 6 条内置规则不可达；NER 超时/超载静默丢结果（`internal/pii_next/ner/presidio.go:82-85`）。
- **做法**：regex/builtin 接入 pipeline 路径或删除字段（加载时报错而非静默忽略）；NER 失败加计数器+审计 note。
- **验证**：配置 regex 规则后确认生效或启动即报错。

---

## 第三批：性能与健壮性（可延后）

- **P3-1 WAL 批量化**：`internal/session/wal.go:97` 每映射一次 fsync（脱敏热路径最大延迟源）→ 批量/异步刷盘；加 WAL compaction/轮转（当前无界增长）。
- **P3-2 替换单趟化**：`internal/redact/engine.go:258-275`、`internal/pii_next/pipeline/pipeline.go:145-167` 逐 match 三重 append，O(n·m) → 单趟 builder。
- **P3-3 占位符注册原子化**：`LookupReverse → GeneratePlaceholder → Register`（`engine.go:265-269` + `internal/session/manager.go:129-143`）合并为单次持锁 `GetOrCreatePlaceholder`，消除 TOCTOU。
- **P3-4 占位符格式加固**：`internal/restore/engine.go:35` 正则加尾部边界；可嵌入 2 位校验位降低误还原；映射丢失（TTL/驱逐）时审计打"未还原占位符残留"标记。
- **P3-5 AC 自动机**：`internal/ahocorasick/matcher.go:18-22` `map[byte]int` → 排序数组/双数组；关键词大小写不敏感选项。
- **P3-6 请求侧 content-type 对齐响应侧**：`proxy.go:1063-1075` 支持 `+json`、缺 content-type 时 sniff；评估 multipart 文本 part 脱敏。
- **P3-7 WebSocket 加固**：permessage-deflate 坚持时主动解压而非整连接放弃（`proxy.go:741-743`）；帧解析失败记审计（`transform_conn.go:134-140`）；下行跨消息 buffer。

## 审计合规增强（独立一批，按需要做）

- 导出：`GET /manager/api/audit/export?from=&to=&category=&format=csv|json`（查询层 `internal/auditdb/store_sqlite.go:184-230` 目前只有 LIMIT）。
- 防篡改：`audit_events` 加 `prev_hash`/`row_hash` 链式列 + verify API（schema 在 `store_sqlite.go:18-37`）。
- 告警：命中阈值触发 webhook/日志（挂点 `proxy.go:617-641` 或 `internal/admin/admin.go:76`）。
- 统计聚合持久化：按 category/host/小时聚合（现状仅 4 个内存计数器，`internal/admin/api_stats.go:10-63`）。
- 最小化采集：`pass_through` 流量默认不落持久层（`proxy.go:460-464` + `admin.go:76-90`）。
- 内存审计上限 200 做成配置（`internal/admin/admin.go:50`）。
- 文档警示：`proxy.listen` 配 `0.0.0.0` 会暴露 admin 面板且无 CSRF token（`internal/config/config.go:151`、`internal/admin/auth.go:302-311`）。

## 完成定义（DoD）

每完成一条：代码 + 同步配置模板/文档 + 相关包测试通过 + `go build/vet/test` 全绿 + commit（Conventional Commits）+ 在本文件勾选状态。全部批次完成后做一轮端到端验证：真实 CLI（kimi/opencode）经代理发送含密钥的请求 → 上游收到占位符 → 响应还原 → 审计只有 preview。

## 状态追踪

| 编号 | 状态 |
|---|---|
| P1-1 invalid_json 回退 | ☑ |
| P1-2 JSON 字段覆盖 | ☑ |
| P1-3 system-reminder 豁免 | ☑ |
| P1-4 SSE delta 还原 | ☑ |
| P1-5 审计库防泄密 | ☑ |
| P2-1 归一化防绕过 | ☑ |
| P2-2 元审计+防爆破 | ☑ |
| P2-3 中文 PII+校验位 | ☑ |
| P2-4 订阅防投毒 | ☑ |
| P2-5 死代码收敛 | ☑ |
| P3 系列 | ☐（可拆分勾选） |
| 审计合规增强 | ☐（按需） |
