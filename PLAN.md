# PLAN.md — VibeGuard 优化计划（2026-09 安全 + 易用性审查）

> 本文档是当前优化批次的工作计划。此前的 P1–P3 加固/性能批次已全部完成（见 git 历史与 AGENTS.md）。

## 背景与调研结论

目标场景：日常使用 **Kimi Code 与 opencode**，维护**自定义敏感词列表**，要求脱敏操作方便快捷。

代码审查（只读，未修改）结论摘要：

- 安全基线整体良好：bcrypt 管理认证 + 防爆破锁定、审计默认不落原文（preview 降级）、SQLite 文件 0600、占位符 HMAC 校验、订阅 sha256 pin 常量时间比较、RE2 无 ReDoS、上游 TLS 强制校验。
- 主要风险集中在：Admin API 缺少 CSRF 防护、setup 端点"先到先得"、项目级 `.vibeguard.yaml` 注入面、默认规则订阅无 pin 且 fail-open、CA regenerate 假成功。
- 主要易用性缺口集中在：无 CLI 加词命令、本地 `.vgrules` 手改后不热加载且语法错误静默跳过、`vibeguard test` 不加载真实配置、审计不标注命中规则来源、`opencode.ai` 不在默认 targets。

---

## 第一批（P1）：自定义敏感词易用性 —— 高价值低成本

| # | 事项 | 涉及文件 | 状态 |
|---|------|----------|------|
| P1-1 | 新增 `vibeguard rules add/remove/list` CLI：直接读写 `patterns.keywords`，走 `config.Manager.Update` 落盘（自动获得热加载 + 落盘加密），支持 `--category`、去重、中文输出 | `cmd/vibeguard/main.go`、（必要时）`internal/config` | ✅ |
| P1-2 | 热加载监听本地规则文件与 secret_files：`Manager.Watch` 目前只认 `config.yaml`/`.vibeguard.yaml`；把 `rule_lists[].path`、`secret_files[].path` 纳入监听（或其父目录 + 按文件名过滤），变更即触发 `ReloadFromConfig` | `internal/config/config.go`、`internal/proxy/proxy.go` | ✅（P1 批已完成，2026-09-15） |
| P1-3 | 默认 targets 补 `opencode.ai`；init 模板（zh + en）补本地 `rule_lists` path 示例和 keywords 条目示例（三处同步；proxy/targets 段保持 tab 缩进） | `internal/config/config.go`、`cmd/vibeguard/main.go` | ✅ |
| P1-4 | 文档：README 增加"三步添加敏感词"食谱（管理页路径 + .vgrules 路径 + 新 CLI），注明 `~/.vibeguard/rules/local/` 目录与热加载行为；`docs/RULE_LISTS.md` 补本地文件来源/生效/排错说明 | `README.md`、`docs/RULE_LISTS.md` | ✅ |

验收：`go build ./... && go build -tags vibeguard_full ./... && go vet ./... && go test ./...`（容忍既有上游问题：wsproxy 的 vet 报错、auditdb 的 gofmt）；新 CLI 用临时 HOME 做端到端冒烟（add → list → remove；改 .vgrules 后无需重启即生效）。**全部通过（2026-09-15）**；守护进程日志确认 `.vgrules` 编辑触发 "Referenced rule/secret file changed, reloading..."、"rules add" 触发 keywords 1→2 热重载。

> P1 实施中发现的既有限制（记入 P3-4 一并处理）：`Manager.Update` 会把「全局+项目合并后」的整份配置写回全局 config.yaml，在含 `.vibeguard.yaml` 的目录里执行 `rules add/remove` 会把项目级关键词固化进全局配置。CLI 已加警告提示。

## 第二批（P2）：安全必修

| # | 事项 | 位置 | 状态 |
|---|------|------|------|
| P2-1 | Admin API CSRF 防护：校验 `Origin`/`Sec-Fetch-Site`，或要求自定义头（写操作必须预检）。重点保护 `POST /manager/api/certificates/trust`、`/regenerate`（SameSite=Strict 不防同站跨端口） | `internal/admin/handler.go`、`internal/admin/auth.go` | ✅（写操作须带 `X-VG-Admin-Request: 1` + Origin/Sec-Fetch-Site 校验，前端全部请求补头；2026-09-18） |
| P2-2 | `/manager/api/auth/setup` 仅接受直连 loopback 请求；代理路由对 absolute-URI 代理请求的 `/manager/` 前缀分流加 Host 校验 | `internal/admin/handler.go:96`、`internal/proxy/proxy.go:187` | ✅（setup 要求 origin-form + loopback RemoteAddr；代理路由仅 origin-form 才进管理端；2026-09-18） |
| P2-3 | CA regenerate 真正轮换：删除/备份旧 `ca.key`/`ca.crt` 后再生成，并明确提示 WAL 与加密配置将不可解密 | `internal/admin/api_certs.go:94` | ✅（旧 CA 备份为 *.bak、失败回滚；响应明确提示 WAL/加密关键词不可解密 + 需重新信任；2026-09-18） |
| P2-4 | 规则解析失败可见化：`RuleListItem` 增加 `last_error`，管理页标红（本地列表目前只有 `exists`） | `internal/proxy/proxy.go:1366`、`internal/admin/api_rule_lists.go`、管理页前端 | ✅（proxy 每次重载全量上送本地列表加载错误 `SetLocalRuleListErrors`，修复后自动清除；前端红色失败标签；2026-09-18） |
| P2-5 | 非 loopback 监听启动/热加载时 Warn + 管理页横幅提示 | `internal/proxy/proxy.go` | ✅（启动与热加载检测，`/manager/api/settings` 暴露 `non_loopback_warning`，前端顶部红色横幅；2026-09-18） |

## 第三批（P3）：体验增强

| # | 事项 | 位置 | 状态 |
|---|------|------|------|
| P3-1 | `vibeguard test --text "..."` 升级为加载真实配置的干跑，输出命中分类/规则来源/placeholder；保留现 keyword 模式 | `cmd/vibeguard/main.go`、`internal/pii_next/pipeline` | ✅（`cmd/vibeguard/test_dryrun.go`，镜像 proxy 组装逻辑，临时 session 目录不污染真实环境；2026-09-18） |
| P3-2 | 审计命中标注来源规则（rule name / rule list name） | `internal/redact`、`internal/pii_next`、`internal/proxy/proxy.go:360`、`internal/admin/audit.go` | ✅（`redact.Match.Source` 源头填充 → proxy 拷贝 → `AuditMatch.Source` + auditdb 持久化 + 前端展示；2026-09-18） |
| P3-3 | 默认规则订阅内置 sha256 pin（或默认 tofu）；连续失败时管理页显著告警 | `internal/config/config.go:202`、`internal/rulelists` | ✅（空 pin/`"tofu"` 一律 TOFU，固定 hex pin 优先；meta 新增 `consecutive_failures`，≥2 次管理页红色告警；2026-09-18） |
| P3-4 | 项目级 `.vibeguard.yaml` 的安全敏感字段（audit_db、listen、rule_lists URL、intercept_mode）默认忽略或需显式确认；reload 日志 Warn 列出项目覆盖项 | `internal/config/config.go:399` | ✅（全局 `allow_project_sensitive_overrides: false` 默认过滤四类字段并逐项 Warn；2026-09-18） |
| P3-5 | `vibeguard trust` / init 向导打印 CA 风险提示（key 位置、0600 边界、卸载方法） | `cmd/vibeguard/main.go:1221`、`internal/cert/trust.go` | ✅（双语三行提示：私钥 0600 仅防其他用户、同用户恶意软件可冒签、uninstall.sh/手动删 CA；2026-09-18） |
| P3-6 | 管理页加"试跑"小工具；端口占用/CA 未信任的引导文案；本机安装可选写 `kimi`/`opencode` 快捷 alias | `internal/admin`、`install.sh`、`install.ps1` | ✅（`POST /manager/api/test` + 规则页"脱敏试跑"卡片；端口占用双语引导；install.sh 可选 alias（rc 幂等写入）、install.ps1 打印 function 示例；2026-09-18） |

## 低优先级记录（暂不计划）

- 存储密钥派生缺域分离（`internal/cert/ca.go:178`，WAL 与 pattern 加密共用一钥）
- debug 抓包 URL 未 mask query（Gemini `?key=`，`internal/proxy/proxy.go:513`）
- HTTP server 无 `ReadHeaderTimeout`（slowloris，localhost 风险有限）
- 登录锁定为进程级全局（本机恶意进程可持续锁合法用户）
- 会话 token 无 idle timeout、登录后不轮换
- wsproxy 未压缩消息缓冲无上限（`internal/wsproxy/transform_conn.go`）
- precheck.mjs 自定义 regex 走 JS 回溯引擎（本地可信文件，风险低）
- 配置目录创建权限 0755 不一致（`cmd/vibeguard/main.go:895`）
- 默认 `intercept_mode: global` 解包所有 CONNECT（文档应推荐 targets 模式给注重隐私的用户）
- 订阅管理端点 SSRF 面（需认证、仅本机，风险低）
- 叶子证书带多余 `ExtKeyUsageClientAuth`（`internal/cert/leaf.go:94`）
