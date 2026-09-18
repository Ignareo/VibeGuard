# VibeGuard Precheck — Kimi Code 插件

VibeGuard 的 Kimi Code 配套插件。由于 Kimi Code 的插件/Hook API 目前无法**改写**发往模型的消息，本插件采用"预检拦截"模式作为代理方案的补充：

- `UserPromptSubmit`：用户提交消息前扫描，命中敏感内容则**阻止本轮请求**并提示；
- `PreToolUse`（Bash）：执行 shell 命令前扫描命令文本，命中则阻止；
- 内置常见凭据形态检测（API key、GitHub token、AWS AKIA、JWT、私钥块等），并支持在 `patterns.json` 中追加自定义关键词/正则；
- 不会把命中的密钥本身打印到任何地方（只输出规则名）；
- Fail-open：脚本出错或超时默认放行，不阻塞工作（Kimi Code Hook 的设计约束）。

> 想要"透明脱敏 + 自动还原"（敏感内容照常发送、以占位符形式出网），请使用代理方案：`vibeguard kimi`。

## 安装

方式一（插件，推荐）：在 Kimi Code TUI 中：

```
/plugins install <本仓库路径>/integrations/kimi-code-vibeguard
/reload
```

或直接从 GitHub 安装：`/plugins install https://github.com/Ignareo/VibeGuard/tree/main/integrations/kimi-code-vibeguard`

方式二（全局 hooks，免插件管理器）：在 `~/.kimi-code/config.toml` 末尾追加：

```toml
[[hooks]]
event = "UserPromptSubmit"
command = "node <本仓库路径>/integrations/kimi-code-vibeguard/hooks/precheck.mjs"
timeout = 5

[[hooks]]
event = "PreToolUse"
matcher = "Bash"
command = "node <本仓库路径>/integrations/kimi-code-vibeguard/hooks/precheck.mjs"
timeout = 5
```

> 注意：hook payload 中 `prompt` 是 content parts 数组（`[{type:"text", text:"..."}]`），本脚本已兼容该格式与纯字符串两种形态。

## 配置

编辑插件根目录下的 `patterns.json`（安装后位于 `$KIMI_CODE_HOME/plugins/managed/vibeguard-precheck/`）：

```json
{
  "enabled": true,
  "keywords": ["my-internal-secret", { "value": "sk-xxxx", "label": "company-gateway-key" }],
  "regex": [{ "pattern": "internal\\.example\\.com", "label": "internal-host" }]
}
```

- `enabled: false` 或配置文件缺失时插件为空操作；
- `keywords` 为精确子串匹配；`regex` 为正则；`label` 用于拦截提示中显示的规则名；
- 修改后执行 `/plugins reload` 生效。

## 测试

```bash
echo '{"hook_event_name":"UserPromptSubmit","prompt":"my key is sk-abc123def456ghi789jkl"}' \
  | node hooks/precheck.mjs; echo "exit=$?"
# 输出拦截提示，exit=2
```
