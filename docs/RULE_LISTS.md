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

## 订阅

订阅只需一个 URL。VibeGuard 会做基本安全检查（大小限制、文本解析、正则编译）并把拉取内容缓存到本地：

- 订阅缓存目录：`~/.vibeguard/rules/subscriptions/`
- 管理页入口：`/manager/#/rule_lists`

### 订阅完整性（sha256_pin）

HTTPS + 解析校验挡不住"规则源本身被攻陷后推送恶意规则"。给 `rule_lists` 条目加 `sha256_pin` 可钉扎内容哈希：

```yaml
patterns:
  rule_lists:
    - name: my-rules
      url: https://example.com/rules.vgrules
      sha256_pin: tofu        # 或期望内容的 64 位 hex sha256
      enabled: true
```

- `tofu` —— 首次信任：首个被接受的内容哈希记入订阅元数据（`pinned_sha256`），之后哈希不符的更新被拒绝。
- 64 位 hex —— 内容 sha256 必须完全一致。

被拒绝的更新会保留现有本地缓存、在订阅元数据里写 `last_error`（管理页可见）并打告警日志。若上游是正常更新，把 pin 改成新哈希，或删掉订阅元数据文件里的 `pinned_sha256`。

## 公开规则列表

欢迎通过 PR 把你的规则列表加到下表（按名称字母序，附简短说明）。

| 名称 | URL | 说明 |
|------|-----|------|
| Default Rules | `https://raw.githubusercontent.com/Ignareo/VibeGuard/refs/heads/main/internal/defaultrules/default.vgrules` | 内置规则：邮箱、电话、IP、UUID、SSN、IBAN、信用卡（Luhn）、银行卡（Luhn）、MAC、加密货币地址、API 密钥、中国身份证（校验位）、中国护照、统一社会信用代码（校验位）等 |
