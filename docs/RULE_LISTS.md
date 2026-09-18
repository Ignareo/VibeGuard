# 规则列表（.vgrules）

VibeGuard 的规则列表是纯文本文件，逐行解析。空行与注释行（以 `#`、`//`、`;`、`!` 开头）会被忽略。

## 语法

```
# 注释以 #、//、;、! 开头
keyword <类别> <文本...>        # 子串匹配（在归一化文本上：大小写折叠、零宽字符剔除、NFKC）
regex   <类别> <RE2正则> [:: <校验器>]
                                # Go RE2 正则；含捕获组时优先替换第一个捕获组
```

- `keyword`：精确子串匹配，适合人名、项目代号、密钥片段。
- `regex`：Go RE2 正则，适合邮箱/手机号/证件号等模式。若含捕获组，只替换**第一个捕获组**的区间（更安全，避免把参数名一起抹掉）。
- 类别名归一化为 `[A-Z0-9_]`。

### 校验位验证器

`regex` 规则可加 `:: <校验器>` 后缀，对捕获文本做校验位验证，验证不通过的命中直接丢弃（大幅降低纯数字 ID 的误报）：

- `:: luhn` —— 银行/信用卡号（校验前剔除非数字字符）
- `:: china_id` —— 中国居民身份证号（GB 11643 校验位）
- `:: uscc` —— 统一社会信用代码（校验位）

未知校验器名称会在解析时报错。

完整示例见 [rule_lists.sample.vgrules](rule_lists.sample.vgrules)。

## 本地规则文件

除订阅外，也可以直接引用本地 `.vgrules` 文件：

- 推荐把文件放在 `~/.vibeguard/rules/local/`；管理页 `#/rule_lists` 上传的文件也落盘到该目录。
- 在 `config.yaml` 中用 `path` 条目引用（init 模板已含此示例）：

```yaml
patterns:
  rule_lists:
    - name: my-local
      path: ~/.vibeguard/rules/local/my.vgrules
      enabled: true
```

- 保存文件即自动热重载，无需重启代理（`secret_files` 同理）。
- 语法错误不影响其它规则：解析失败的整个列表被跳过（该列表规则不生效），管理页该列表显示红色错误详情，日志同时有 Warn；修复并保存文件后热重载自动恢复。

## 订阅

订阅只需一个 URL。VibeGuard 会做基本安全检查（大小限制、文本解析、正则编译）并把拉取内容缓存到本地：

- 订阅缓存目录：`~/.vibeguard/rules/subscriptions/`
- 管理页入口：`/manager/#/rule_lists`

### 订阅完整性（sha256_pin）

HTTPS + 解析校验挡不住"规则源本身被攻陷后推送恶意规则"。`sha256_pin` 用于钉扎内容哈希。**自 2026-09 批次起，留空（默认）即启用 TOFU 钉扎**，不再 fail-open：

```yaml
patterns:
  rule_lists:
    - name: my-rules
      url: https://example.com/rules.vgrules
      sha256_pin: tofu        # 留空等价于 tofu；或填期望内容的 64 位 hex sha256
      enabled: true
```

- 留空（默认）或 `tofu` —— 首次信任：首个被接受的内容哈希记入订阅元数据（`pinned_sha256`），之后哈希不符的更新被拒绝（固定 64 位 hex pin 优先级最高，不受 TOFU 影响）。
- 64 位 hex —— 内容 sha256 必须完全一致。

被拒绝的更新会保留现有本地缓存、在订阅元数据里写 `last_error`（管理页可见）并打告警日志；元数据里的 `consecutive_failures` 记录连续同步失败次数（成功即清零），管理页在连续失败 ≥2 次时显示红色显著告警。若上游是正常更新，把 pin 改成新哈希，或删掉订阅元数据文件里的 `pinned_sha256`。

## 公开规则列表

欢迎通过 PR 把你的规则列表加到下表（按名称字母序，附简短说明）。

| 名称 | URL | 说明 |
|------|-----|------|
| Default Rules | `https://raw.githubusercontent.com/Ignareo/VibeGuard/refs/heads/main/internal/defaultrules/default.vgrules` | 内置规则：邮箱、电话、IP、UUID、SSN、IBAN、信用卡（Luhn）、银行卡（Luhn）、MAC、加密货币地址、API 密钥、中国身份证（校验位）、中国护照、统一社会信用代码（校验位）等 |
