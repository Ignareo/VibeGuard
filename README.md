<p align="center">
  <img src="./image/logo.jpg" alt="VibeGuard" width="720"><br><br>
  <span>仅仅 1% 内存占用，给你 99% 隐私保护。</span><br><br>
  <a href="LICENSE"><img alt="License" src="https://img.shields.io/github/license/Ignareo/VibeGuard"></a>
  <a href="go.mod"><img alt="Go 版本" src="https://img.shields.io/github/go-mod/go-version/Ignareo/VibeGuard"></a>
</p>

> **Fork 声明**：
>
> 本仓库是 [inkdust2021/VibeGuard](https://github.com/inkdust2021/VibeGuard) 的个人 fork（[Ignareo/VibeGuard](https://github.com/Ignareo/VibeGuard)），基于 Apache-2.0 协议修改。新增 **Kimi Code 支持**（`vibeguard kimi` 代理模式与 `integrations/kimi-code-vibeguard` 预检插件）以及一批安全/性能强化，详见下文 [「本 Fork 相对上游的改动」](#本-fork-相对上游的改动)（完整清单见 [PLAN.md](PLAN.md)）。与上游项目无关联；fork 特有的改动请勿向上游提交 issue。

VibeGuard 是一个轻量化的本地 MITM HTTPS 代理：在你用 AI 编程助手（Claude Code / Codex / Kimi Code / OpenCode……）时，把发往大模型 API 的请求中的密钥、手机号、身份证等敏感信息替换为占位符（如 `__VG_EMAIL_9811f8394a1628__`），收到响应后再还原回来。模型看到的是占位符，你看到的是原文。

**隐私声明**：匹配/脱敏全部在本地完成，不会把原始敏感内容上传到任何 VibeGuard 自有服务器或第三方分析服务；只有**脱敏后的内容**按你的配置转发给上游 AI 服务。

## 文档导航

- **本文档**：安装与使用说明。
- [docs/TECHNICAL.md](docs/TECHNICAL.md)：技术架构与实现细节（面向开发者）。
- [docs/RULE_LISTS.md](docs/RULE_LISTS.md)：`.vgrules` 规则列表语法与订阅完整性（sha256 钉扎）。

## 安装

本 fork 目前**未发布预编译 Release**，安装脚本会自动回退到源码构建（需要 Go 1.24+ 与 git；发布 Release 后会优先下载预编译二进制）。

```bash
# macOS / Linux（一键脚本）
curl -fsSL https://raw.githubusercontent.com/Ignareo/VibeGuard/main/install | bash

# 或克隆后安装（推荐用于本地开发/调试）
git clone https://github.com/Ignareo/VibeGuard.git
cd VibeGuard && bash install.sh
```

```powershell
# Windows（PowerShell，一键脚本）
powershell -NoProfile -ExecutionPolicy Bypass -Command "irm https://raw.githubusercontent.com/Ignareo/VibeGuard/main/install.ps1 | iex"

# 或克隆后安装
git clone https://github.com/Ignareo/VibeGuard.git
cd VibeGuard
powershell -NoProfile -ExecutionPolicy Bypass -File .\install.ps1
```

安装脚本会生成 CA 证书、写入默认配置并引导信任 CA。手动源码安装：在仓库内执行 `go install ./cmd/vibeguard` 后运行 `vibeguard init`。Docker 部署：在仓库内执行 `bash install.sh --method docker`，或 `docker compose -f docker-compose.source.yml up -d`（均为本地构建镜像）；发布 Release 后也可直接 `docker compose up -d` 拉取 `ghcr.io/ignareo/vibeguard`。

> 上游的一键安装（`https://vibeguard.top/install`）安装的是上游原版，不包含本 fork 的改动。

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

## 本 Fork 相对上游的改动

本仓库在 2026-09 做了一轮「Kimi Code 支持 + 安全/性能强化」。完整工作清单见 [PLAN.md](PLAN.md)，实现细节见 [docs/TECHNICAL.md](docs/TECHNICAL.md)。

### Kimi Code 支持

- **代理模式（透明脱敏 + 自动还原）**：`vibeguard kimi [args...]`；默认拦截目标新增 `api.kimi.com`、`api.moonshot.cn`、`api.moonshot.ai`（`opencode.ai` 也在默认列表）。
- **预检插件**：`integrations/kimi-code-vibeguard/` —— Kimi Code 插件（`vibeguard-precheck`），在敏感内容发给模型前**拦截**包含密钥的用户输入和 `Bash` 命令。Kimi Code 的插件/Hook API 无法改写出站消息，因此该插件是代理模式的补充而非替代，详见其 README。
- **默认规则订阅**改指向本 fork 的 `internal/defaultrules/default.vgrules`；旧的上游默认订阅 URL 会在加载时自动迁移。

### 安全强化

- **防绕过归一化**：匹配前剔除零宽字符、NFKC 折叠、大小写折叠，并把命中区间映射回原文（`password`、全角数字等绕过失效）。
- **审计不落原文**：默认只存 `previewValue`（前 2…后 2 位），`audit_db.persist_raw_values` 显式开启才落原文；命中附带来源规则（`rulelist:<名>` / `keywords` / `ner-presidio`）。
- **管理端加固**：写 API 要求 `X-VG-Admin-Request: 1` 并校验 `Origin`/`Sec-Fetch-Site`（CSRF）；`/auth/setup` 仅限本机 loopback 直连；只有 origin-form 请求会路由到管理端；登录连续失败指数退避；管理操作元审计；CA 重新生成会备份并轮换旧文件；非 loopback 监听在管理页显示红色横幅。
- **项目配置防注入**：项目级 `.vibeguard.yaml` 默认不能覆盖 `audit_db`、`proxy.listen`、`proxy.intercept_mode`、规则订阅 URL，除非显式开启 `allow_project_sensitive_overrides`。
- **订阅防投毒**：`sha256_pin` 留空即 TOFU 钉扎，重定向目标复检；元数据记录 `last_error` 与 `consecutive_failures`（连续失败 ≥2 次管理页红色告警）。
- **结构化脱敏补全**：覆盖 system prompt、tool 调用/结果、content parts；不再豁免 `<system-reminder>`；替换破坏 JSON 时按命中粒度回退，`invalid_json_policy=allow` 落地。
- **占位符更稳**：新增 2 位校验位与尾部边界检查，旧 12 位格式继续兼容；残留占位符写入审计 note。
- **WebSocket（beta）**：permessage-deflate 帧解压后脱敏（以未压缩帧转发）、帧协议校验、解析失败审计、跨消息还原。
- **流式还原修复**：chat.completions 与 tool-call SSE delta 中的占位符正确还原。

### 性能与体验

- 关键词匹配（Aho-Corasick）改为排序数组转移 + 根节点直查表；脱敏请求体单趟重建。
- 会话映射 `GetOrCreatePlaceholder` 原子化（并发同文只产生一个占位符）；WAL 批量 fsync（`session.wal_sync_interval`）并自动压缩（`session.wal_compact_bytes`）。
- 请求侧 Content-Type 处理与响应侧对齐：mime 解析、缺类型时嗅探 JSON、`multipart/form-data` 按 part 脱敏。
- 本地 `.vgrules` / `secret_files` 保存后自动热重载；解析错误在管理页对应列表标红。
- 新 CLI：`vibeguard rules add/remove/list`（关键词落盘加密）、`vibeguard test --text`（加载真实配置干跑）。
- 管理页新增「脱敏试跑」工具、端口占用/CA 未信任引导；`install.sh` 可选写入 `kimi`/`opencode` alias。

对 OpenCode 也可以选择进程内插件 [opencode-vibeguard](https://github.com/inkdust2021/opencode-vibeguard)，完全不需要代理。

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
| `vibeguard test --text "..."` | 按真实配置干跑一段文本：输出每个命中的分类、来源规则、占位符与掩码预览（不写会话、不联网拉取订阅） |
| `vibeguard rules list` | 列出关键词及分类 |
| `vibeguard rules add <词> [--category <分类>]` | 添加关键词（去重、落盘加密，运行中的代理自动热加载） |
| `vibeguard rules remove <词>` | 删除关键词 |
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
| `proxy.listen` | `127.0.0.1:28657` | 监听地址。**不要**改成 `0.0.0.0`——会把管理面板暴露给局域网（此时启动会 Warn、管理页显示红色横幅） |
| `proxy.intercept_mode` | `global` | `global` 拦截全部 HTTPS；`targets` 只拦截 `proxy.targets` 里的域名 |
| `proxy.invalid_json_policy` | `partial` | 脱敏导致 JSON 非法时的策略：`partial`（按命中粒度跳过）/ `allow`（放行原文）/ `block`（拒绝请求） |
| `proxy.websocket_redaction_beta` | `false` | WebSocket 脱敏（beta，主要面向 Codex） |
| `patterns.ner.enabled` | `false` | NER 实体识别（需自备 Presidio Analyzer） |
| `session.ttl` / `session.max_mappings` | `1h` / `100000` | 占位符映射的存活时间与上限 |

## 规则系统

推荐优先级：**关键词列表**（精确子串，适合人名/项目代号/密钥片段）→ **`.vgrules` 规则列表**（正则+校验位，适合邮箱/手机号/身份证等通用模式）→ **NER**（适合难以枚举的人名/地名/机构名）。

管理页入口：规则列表 `#/rule_lists`，关键词 `#/keywords`，NER `#/ner`。语法与订阅钉扎详见 [docs/RULE_LISTS.md](docs/RULE_LISTS.md)。

### 快速添加敏感词

三条路径任选，**运行中的代理会自动热加载，无需重启**（本地 `.vgrules` 文件与 `secret_files` 保存后同样自动热重载）：

1. **CLI（推荐给命令行用户）**——关键词去重后落盘加密保存（机制同 `~/.vibeguard/config.yaml` 中的关键词）：

   ```bash
   vibeguard rules add "内部项目代号" --category PROJECT
   vibeguard rules list                      # 查看现有关键词及分类
   vibeguard rules remove "内部项目代号"
   ```

2. **管理页**——打开 `#/keywords` 添加关键词，即时生效。

3. **`.vgrules` 规则文件**（适合批量导入 / 正则 / 校验位验证器）——编辑 `~/.vibeguard/rules/local/my.vgrules`（init 模板已含 `path` 引用示例），保存即热重载；也可在 `#/rule_lists` 上传文件。语法见 [docs/RULE_LISTS.md](docs/RULE_LISTS.md)。

NER 需自备 [Presidio Analyzer](https://microsoft.github.io/presidio/) 部署并配置 `patterns.ner.presidio_url`；中文识别需显式设置 `patterns.ner.language: "zh"` 且 Presidio 端装有中文模型（如 `zh_core_web_sm` + `jieba`），详见 [docs/TECHNICAL.md](docs/TECHNICAL.md#ner)。

## 如何确认生效

1. `vibeguard start` 启动代理；
2. 经 VibeGuard 启动助手（`vibeguard kimi/claude/...`），或给 IDE/应用设置代理 `http://127.0.0.1:28657`；
3. 先用 `vibeguard test --text "包含敏感词的句子"` 本地干跑验证规则命中（分类/来源/占位符），再发真实对话；
4. 打开 `/manager/` 的 **Audit** 面板：每条请求显示是否进入扫描、命中次数、命中预览（`ab…yz` 形式，不含完整原文）与来源规则。规则列表页还有"脱敏试跑"小工具，管理页内即可验证规则。

## 管理端安全

- 首次访问 `http://127.0.0.1:28657/manager/` 会要求设置管理密码（仅接受本机 loopback 直连设置）。
- 密码以 bcrypt 哈希保存于 `~/.vibeguard/admin_auth.json`（权限 `0600`）。
- 登录连续失败会触发指数退避锁定；管理操作（改配置/规则等）会写入元审计。
- 管理 API 写操作要求自定义头 `X-VG-Admin-Request` 并校验 `Origin`/`Sec-Fetch-Site`（CSRF 防护）；代理只会把**直连**请求路由到管理端，经代理转发的请求即使路径撞上 `/manager/` 也不会到达管理 API。
- 忘记密码：`vibeguard stop` 后删除 `~/.vibeguard/admin_auth.json`，刷新 `/manager/` 重新设置。

## 卸载

macOS / Linux：

```bash
curl -fsSL https://raw.githubusercontent.com/Ignareo/VibeGuard/main/uninstall.sh | bash                    # 卸载
curl -fsSL https://raw.githubusercontent.com/Ignareo/VibeGuard/main/uninstall.sh | bash -s -- --purge      # 连配置一起删
curl -fsSL https://raw.githubusercontent.com/Ignareo/VibeGuard/main/uninstall.sh | bash -s -- --docker     # 卸载 docker 部署
```

Windows（PowerShell）：

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/Ignareo/VibeGuard/main/uninstall.ps1)))"
powershell -NoProfile -ExecutionPolicy Bypass -Command "& ([ScriptBlock]::Create((irm https://raw.githubusercontent.com/Ignareo/VibeGuard/main/uninstall.ps1))) -Purge"
```

卸载脚本会尝试自动移除信任库中的 "VibeGuard CA"；失败时请手动移除。

## 截图

![cc](./image/cc.png)

## License

Apache-2.0（与上游一致），见 [LICENSE](LICENSE)。
