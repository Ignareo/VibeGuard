<p align="center">
  <img src="./image/logo.jpg" alt="VibeGuard" width="720"><br><br>
  <span>仅仅 1% 内存占用，给你 99% 隐私保护。</span><br><br>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/inkdust2021/VibeGuard"></a>
  <a href="go.mod"><img alt="Go 版本" src="https://img.shields.io/github/go-mod/go-version/inkdust2021/VibeGuard"></a>
</p>

> **Fork 声明**：本仓库是 [inkdust2021/VibeGuard](https://github.com/inkdust2021/VibeGuard) 的个人 fork，基于 Apache-2.0 协议修改。新增 **Kimi Code 支持**（`vibeguard kimi` 代理模式与 `integrations/kimi-code-vibeguard` 预检插件）以及一批安全/性能强化（见 [PLAN.md](PLAN.md)）。与上游项目无关联；fork 特有的改动请勿向上游提交 issue。

VibeGuard 是一个轻量化的本地 MITM HTTPS 代理：在你用 AI 编程助手（Claude Code / Codex / Kimi Code / OpenCode……）时，把发往大模型 API 的请求中的密钥、手机号、身份证等敏感信息替换为占位符（如 `__VG_EMAIL_9811f8394a1628__`），收到响应后再还原回来。模型看到的是占位符，你看到的是原文。

**隐私声明**：匹配/脱敏全部在本地完成，不会把原始敏感内容上传到任何 VibeGuard 自有服务器或第三方分析服务；只有**脱敏后的内容**按你的配置转发给上游 AI 服务。

## 文档导航

- **本文档**：安装与使用说明。
- [docs/TECHNICAL.md](docs/TECHNICAL.md)：技术架构与实现细节（面向开发者）。
- [docs/RULE_LISTS.md](docs/RULE_LISTS.md)：`.vgrules` 规则列表语法与订阅完整性（sha256 钉扎）。

## 安装

```bash
# macOS / Linux
curl -fsSL https://vibeguard.top/install | bash

# Windows
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://vibeguard.top/install.ps1 | iex"
```

安装脚本会生成 CA 证书、写入默认配置并引导信任 CA。源码安装：`go install ./cmd/vibeguard` 后运行 `vibeguard init`。

## 快速上手

```bash
# 1. 启动代理（默认后台运行）
vibeguard start

# 2. 通过代理启动你的编程 CLI（只影响该进程，不影响当前终端）
vibeguard kimi [args...]     # 也可换成 claude / codex / opencode / qwen / gemini

# 或者包装任意命令
vibeguard run <command> [args...]

# 3. 打开管理页查看每次请求的命中情况
open http://127.0.0.1:28657/manager/
```

在 IDE / 其他应用中使用：把 HTTP(S) 代理设置为 `http://127.0.0.1:28657`。

## 核心特性

- **三层匹配**：`.vgrules` 规则列表（关键词 + RE2 正则 + 校验位验证器）→ 用户关键词（精确匹配）→ 可选 NER 实体识别（外接 Presidio）。
- **防绕过归一化**：匹配前对文本做零宽字符剔除、NFKC 折叠和大小写折叠，`pass​word`（含零宽字符）、全角数字等绕过手段无效。
- **结构化脱敏**：chat API 的 JSON 请求体按字段精准脱敏（system prompt、tool 调用、多模态 content parts 均覆盖）；JSON 因替换被破坏时按命中粒度回退，不再整体放弃脱敏。
- **占位符可校验**：占位符带 2 位校验位（`__VG_<类别>_<hash12+校验2>__`），还原时可区分"真占位符"和"长得像的文本"，残留占位符会在审计中标记。
- **流式还原**：SSE 逐事件、跨 chunk 还原；WebSocket（beta）支持 permessage-deflate 解压后脱敏/还原。
- **管理页**：`/manager/` 配置规则/证书/会话，Audit 面板查看每次请求的命中预览（只存前 2 后 2 位，默认不落明文），`#/logs` 查看后端调试日志。
- **管理端安全**：bcrypt 密码鉴权 + 登录防爆破 + 操作元审计（谁改了什么配置）。
- **关键词落盘加密**：关键词/排除项在 `~/.vibeguard/config.yaml` 中以密文保存（密钥由本机 CA 私钥派生；管理页仍显示明文）。重新生成 CA 后旧密文无法解密，需重新配置。
- **敏感文件导入（可选）**：通过 `patterns.secret_files` 从 `.env` 等本地文件导入 secret 值并自动脱敏。
- **规则订阅防投毒**：订阅支持 `sha256_pin`（TOFU 或固定哈希）钉扎内容，被篡改的更新会被拒绝。
- **两种拦截模式**：`proxy.intercept_mode: global`（全部 CONNECT 都 MITM）或 `targets`（只拦截列表内域名）。
- **热更新**：管理页修改规则/目标域名无需重启即生效。

## CLI 命令

全局参数：`-c, --config PATH`（默认 `~/.vibeguard/config.yaml`）。

| 命令 | 说明 |
|---|---|
| `vibeguard start [--foreground]` | 启动代理（默认后台；`--foreground` 前台运行） |
| `vibeguard stop` | 停止后台代理 |
| `vibeguard kimi/claude/codex/opencode/qwen/gemini [args...]` | 经代理启动对应 CLI（进程级环境变量注入） |
| `vibeguard run <command> [args...]` | 经代理运行任意命令 |
| `vibeguard init` | 交互式初始化配置与 CA（用安装脚本则无需执行） |
| `vibeguard trust --mode system\|user\|auto` | 把 CA 安装到系统/用户信任库（可能需 sudo） |
| `vibeguard test [pattern] [text]` | 测试脱敏效果（pattern 按关键词精确匹配处理） |
| `vibeguard version` | 版本信息 |
| `vibeguard completion bash\|zsh\|fish\|powershell` | 生成 shell 补全 |

## 配置

- 全局配置：`~/.vibeguard/config.yaml`
- 项目级覆盖：项目根目录 `.vibeguard.yaml`
- 指定路径：`VIBEGUARD_CONFIG=/path/to/config.yaml`

示例——从 `.env` 导入 secret 并自动脱敏（只能防止"发出去"，不能阻止客户端读文件）：

```yaml
patterns:
  secret_files:
    - path: .env
      format: dotenv
      enabled: true
```

常用配置项速查（完整字段见 [docs/TECHNICAL.md](docs/TECHNICAL.md#配置参考)）：

| 字段 | 默认 | 说明 |
|---|---|---|
| `proxy.listen` | `127.0.0.1:28657` | 监听地址。**不要**改成 `0.0.0.0`——会把管理面板暴露给局域网且无 CSRF 防护 |
| `proxy.intercept_mode` | `global` | `global` 拦截全部 HTTPS；`targets` 只拦截 `proxy.targets` 里的域名 |
| `proxy.invalid_json_policy` | `partial` | 脱敏导致 JSON 非法时的策略：`partial`（按命中粒度跳过）/ `allow`（放行原文）/ `block`（拒绝请求） |
| `proxy.websocket_redaction_beta` | `false` | WebSocket 脱敏（beta，主要面向 Codex） |
| `patterns.ner.enabled` | `false` | NER 实体识别（需自备 Presidio Analyzer） |
| `session.ttl` / `session.max_mappings` | `30m` / `100000` | 占位符映射的存活时间与上限 |

## 规则系统

推荐优先级：**关键词列表**（精确子串，适合人名/项目代号/密钥片段）→ **`.vgrules` 规则列表**（正则+校验位，适合邮箱/手机号/身份证等通用模式）→ **NER**（适合难以枚举的人名/地名/机构名）。

管理页入口：规则列表 `#/rule_lists`，关键词 `#/keywords`，NER `#/ner`。语法与订阅钉扎详见 [docs/RULE_LISTS.md](docs/RULE_LISTS.md)。

NER 需自备 [Presidio Analyzer](https://microsoft.github.io/presidio/) 部署并配置 `patterns.ner.presidio_url`；中文识别需显式设置 `patterns.ner.language: "zh"` 且 Presidio 端装有中文模型（如 `zh_core_web_sm` + `jieba`），详见 [docs/TECHNICAL.md](docs/TECHNICAL.md#ner)。

## 如何确认生效

1. `vibeguard start` 启动代理；
2. 经 VibeGuard 启动助手（`vibeguard kimi/claude/...`），或给 IDE/应用设置代理 `http://127.0.0.1:28657`；
3. 在对话中发一条包含测试敏感词的消息（如 `vibeguard test` 先本地验证规则）；
4. 打开 `/manager/` 的 **Audit** 面板：每条请求显示是否进入扫描、命中次数与命中预览（`ab…yz` 形式，不含完整原文）。

## 管理端安全

- 首次访问 `http://127.0.0.1:28657/manager/` 会要求设置管理密码。
- 密码以 bcrypt 哈希保存于 `~/.vibeguard/admin_auth.json`（权限 `0600`）。
- 登录连续失败会触发指数退避锁定；管理操作（改配置/规则等）会写入元审计。
- 忘记密码：`vibeguard stop` 后删除 `~/.vibeguard/admin_auth.json`，刷新 `/manager/` 重新设置。

## 卸载

macOS / Linux：

```bash
curl -fsSL https://vibeguard.top/uninstall | bash                    # 卸载
curl -fsSL https://vibeguard.top/uninstall | bash -s -- --purge      # 连配置一起删
curl -fsSL https://vibeguard.top/uninstall | bash -s -- --docker     # 卸载 docker 部署
```

Windows（PowerShell）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create((irm https://vibeguard.top/uninstall.ps1)))"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create((irm https://vibeguard.top/uninstall.ps1))) -Purge"
```

卸载脚本会尝试自动移除信任库中的 "VibeGuard CA"；失败时请手动移除。

## 本 Fork 新增（Kimi Code）

- **代理模式（透明脱敏 + 自动还原）**：`vibeguard kimi [args...]`；默认拦截目标已包含 `api.kimi.com`、`api.moonshot.cn`、`api.moonshot.ai`。
- **预检插件**：`integrations/kimi-code-vibeguard/` —— Kimi Code 插件（`vibeguard-precheck`），在敏感内容发给模型前**拦截**包含密钥的用户输入和 `Bash` 命令。Kimi Code 的插件/Hook API 无法改写出站消息，因此该插件是代理模式的补充而非替代，详见其 README。

对 OpenCode 也可以选择进程内插件 [opencode-vibeguard](https://github.com/inkdust2021/opencode-vibeguard)，完全不需要代理。

## 截图

![cc](./image/cc.png)

## License

Apache-2.0（与上游一致），见 [LICENSE](LICENSE)。
