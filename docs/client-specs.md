# Client Rule & Configuration Specifications (`client-specs.md`)

本文件是 `zhbcn/Rules` 五端原生编译器（Emitters）与下游私密配置生成器的**唯一技术依据**。所有语法、最优格式、DNS 边界与不支持项均经各客户端官方文档核对，禁止凭印象猜写。

---

## 1. 版本基线与官方文档来源

| 客户端 | 角色 | 目标版本基线 | 官方文档依据 |
| :--- | :--- | :--- | :--- |
| **Mihomo**（Clash Verge Rev / FlClash） | Tier 1 主力（Windows / Android） | Mihomo Meta `v1.19+`（实测 `v1.19.33`） | [Mihomo Wiki](https://wiki.metacubex.one/)、[FlClash](https://github.com/chen08209/FlClash) |
| **Egern** | Tier 1 主力（iOS / iPadOS） | Egern 现行正式版 | [Egern Docs](https://egernapp.com/) |
| **Stash** | Tier 2 自动派生（iOS） | Stash `3.6.0+`（`3.1+` 支持 `.mrs`，`3.6+` 支持 DNS `rule-set`） | [Stash Wiki](https://stash.wiki/) |
| **Loon** | Tier 2 自动派生（iOS） | Loon `Build 1008+`（`DOMAIN-WILDCARD`；`server-dns` 需 `Build 996+`） | [Loon Docs](https://nsloon.app/en/docs/)、[LoonExampleConfig](https://github.com/Loon0x00/LoonExampleConfig) |
| **Quantumult X** | Tier 2 自动派生（iOS） | Quantumult X `1.5.5 build 914+` | [Quantumult-X sample.conf](https://github.com/crossutility/Quantumult-X/blob/master/sample.conf) |

---

## 2. 逐端规范与能力边界

### 2.1 Mihomo（Windows Clash Verge Rev & Android FlClash）

* **最优规则格式**：
  * 纯域名（`DOMAIN`、`DOMAIN-SUFFIX`）与纯 IP（`IP-CIDR`、`IP-CIDR6`）分别拆分并通过官方 CLI 编译为二进制 **`.mrs`（Meta Rule Set）**：
    ```bash
    mihomo convert-ruleset domain text <in.txt> <out_domain.mrs>
    mihomo convert-ruleset ipcidr text <in.txt> <out_ipcidr.mrs>
    ```
    * `domain` 文本源格式：精确域名写 `example.com`，后缀写 `+.example.com`。为保证与 Stash 完全互通，`.mrs` 仅收入 `DOMAIN` 与 `DOMAIN-SUFFIX`。
    * `ipcidr` 文本源格式：每行一个标准 CIDR，**不包含 `no-resolve`**；`no-resolve` 写在主配置 `RULE-SET,<name>,<policy>,no-resolve` 中。
  * 极少量无法转 `.mrs` 的规则（`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`、`DOMAIN-REGEX`、`IP-ASN`、`AND`）独立输出为极小 `classical` YAML（`payload:` 列表），IP/ASN 条目显式带 `,no-resolve`。
* **DNS 绑定机制与限制**：
  * `dns.nameserver-policy` 支持 `'rule-set:<name>'`；Mihomo 在 DNS 阶段仅评估域名规则。
  * **本仓硬约束**：所有在 `bundles.json` 中标记 `dns_bound: true` 的 Bundle，客户端在 `nameserver-policy` 中**强制只绑定纯域名 `.mrs`（`<id>_domain.mrs`）**，杜绝 IP 规则混入 DNS 策略。
  * 支持 `#<策略组名>` 指定 DoH 出站；节点解析使用 `proxy-server-nameserver-policy` 按机场分域指定专用 DoH。
* **平台差异与不支持项**：
  * **不支持**：`PROTOCOL,STUN`（STUN 通过 `fake-ip-filter` 排除 `+.stun.*` + 常规域/IP 分流）、`URL-REGEX`。
  * **Windows（Clash Verge Rev）**：挂载微软基础设施（`ms_connectivity`、`ms_update`）与必要的 Windows `.exe` 进程规则，不挂 Android/iOS 系统规则。
  * **Android（FlClash）**：挂载 Google 基础设施（`google_connectivity`、`google_fcm`、`google_play`）并绑定独立 `Google 服务` 组；**若 `platforms/android.yaml` 未使用任何 Android 包名进程规则，FlClash 默认保持 `find-process-mode: off`**（分应用绕过走客户端原生访问控制），不盲目开启 `strict`；剥离 `.exe` 与 Windows/iOS 噪声。

---

### 2.2 Stash（iOS 3.6+）

* **最优规则格式**：
  * `behavior: domain` 与 `behavior: ipcidr` **直接复用 Mihomo 编译的同一套 `.mrs` 二进制产物**（`dist/mihomo-stash/*.mrs`）。
  * 少量无法转 `.mrs` 的规则输出为独立 `classical` 纯文本（`dist/stash-classical/*.list`，`format: text`），IP/ASN 条目带 `,no-resolve`。
* **逻辑规则与 `AI STUN`（已核对官方文档）**：
  * Stash 原生支持 `AND` / `OR` / `NOT` 逻辑规则以及 `PROTOCOL,STUN`，且支持在 `AND` 中嵌套 `RULE-SET`（如 `AND,((PROTOCOL,STUN),(RULE-SET,aigc_domain)),AIGC` 或联合 `OR` 匹配 `aigc_domain` / `aigc_ipcidr` / `aigc_classical`），其后以 `PROTOCOL,STUN,Public network` 兜底。
* **DNS 绑定机制与限制**：
  * Stash `3.6.0+` 支持在 `dns.nameserver-policy` 中使用 `'rule-set:<name>'`，强制仅绑定纯域名 `.mrs`。
  * **关键坑点**：Stash 中设置全局 `proxy-server-nameserver` 会覆盖分域策略，因此**禁止设置统一 `proxy-server-nameserver`**，节点域名统一写在 `nameserver-policy` 中按机场分域指定 DoH，并配合 `follow-rule: true` 路由 DoH IP。
* **不支持项**：
  * iOS 平台不支持 `PROCESS-NAME` / `PROCESS-PATH`（编译期已从通用源剥离，若出现则显式跳过并记入报告）。

---

### 2.3 Egern（iOS / iPadOS）

* **最优规则格式**：
  * 原生结构化 YAML：`domain_set`、`domain_suffix_set`、`domain_keyword_set`、`domain_wildcard_set`、`domain_regex_set`、`ip_cidr_set`、`ip_cidr6_set`、`asn_set`、`and_set`、`url_regex_set`。
  * 凡含 IP/ASN 的规则集文件，顶层强制写入 `no_resolve: true`；内联 IP 规则逐条写 `no_resolve: true`。
* **逻辑规则与 `AI STUN`**：
  * 原生支持 `and` 嵌套 `protocol: stun` 与 `rule_set`（直接引用 `dist/egern/aigc.yaml`），其后以 `protocol: stun` 兜底至 `Public network`。
* **DNS 绑定机制与限制**：
  * `dns.forward` 使用 `proxy_rule_set` 引用远程 YAML。
  * **本仓硬约束**：当一个 `dns_bound: true` 的 Bundle 同时包含 IP/ASN 规则时，编译器除输出完整路由包 `dist/egern/<id>.yaml` 外，额外输出纯域名包 `dist/egern/<id>_domain.yaml`（零 IP/ASN/URL 规则），供 `dns.forward` 专属引用。
  * Egern 代理 DNS 上游连接强制直连，由路由规则中的 DoH IP 条目控制出口。
* **不支持项**：
  * 不支持 `.mrs`；iOS 不支持进程匹配（通用源已剥离）。

---

### 2.4 Loon（iOS Build 1008+）

* **最优规则格式**：
  * 无策略原生纯文本 `.list`（`dist/loon/<id>.list`），在主配置 `[Remote Rule]` 中通过 `policy=<策略>` 绑定出口。
  * 支持类型：`DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`DOMAIN-WILDCARD`（需 Build 1008+）、`IP-CIDR`、`IP-CIDR6`、`IP-ASN`、`PROTOCOL`、`URL-REGEX`、`AND`/`OR`/`NOT`；IP/ASN 条目强制附加 `,no-resolve`。
* **逻辑规则与 `AI STUN`（已二次核对官方文档）**：
  * Loon 的外部规则文件在 `[Remote Rule]` 区块声明，**不支持在 `[Rule]` 的 `AND` 逻辑规则中嵌套 `RULE-SET`**。
  * **原生替代方案**：编译器专门生成 `dist/loon/aigc_stun.list`，将目标 AI 源（Anthropic / Claude / OpenAI）的每条有效原子规则展平为原生 `AND,((PROTOCOL,STUN),(<atom>))`，在主配置 `[Remote Rule]` 顶部绑定 `policy=AIGC`，紧随其后放 `PROTOCOL,STUN` 绑定 `Public network`。
* **DNS 绑定机制与限制**：
  * **`[Host]` 不支持绑定远程规则集**；节点解析通过 `[Remote Proxy]` 的 `server-dns="..."`（需 Build 996+）按订阅指定；`[Host]` 仅保留少量高优先级核心域名映射，不展开万级大表。
  * **匹配顺序差异**：Loon 按「本地 `[Rule]` 优先于 `[Remote Rule]`，且域名优先于 IP」求值；因此本地引导直连规则须用 `AND,((NOT,((PROTOCOL,STUN))),...)` 避免遮挡前置 STUN 分流。
* **不支持项与适配策略**：
  * **不支持 `DOMAIN-REGEX`**（即使部分社区文档提及，Loon 官方与既有实测以 `DOMAIN-WILDCARD` 为准）：仅允许经审阅的白名单正则转译为 `DOMAIN-WILDCARD`（标记 `LOON-ADAPTED`）；遇到未审阅正则直接编译报错，绝不静默丢弃。
  * iOS 忽略 `PROCESS-NAME` / `PROCESS-PATH`（已剥离，如遇则显式跳过并记入报告）。
  * `URL-REGEX` 在未启用 MITM 时无法拦截 HTTPS 路径，仅保留并标注。

---

### 2.5 Quantumult X（iOS 1.5.5+）

* **最优规则格式**：
  * 纯文本 `.list`（`dist/quantumultx/<id>.list`），行内策略统一写占位符 `proxy`，客户端在 `[filter_remote]` 中通过 `force-policy=<策略>, opt-parser=false` 覆写。
  * 支持类型：`host`、`host-suffix`、`host-keyword`、`host-wildcard`、`ip-cidr`、`ip6-cidr`、`ip-asn`、`geoip`、`user-agent`；远程规则在 `opt-parser=false` 下严格采用三段式 `type,value,proxy`（不导出 `,no-resolve`）。
* **规则类型优先级与跨 Bundle 覆盖风险（关键特性）**：
  * 当 Quantumult X 开启默认的「分流匹配优化（Filter Match Optimization）」时，**匹配不再严格按配置文件书写顺序执行**，而是优先按规则类型由高到低求值：
    1. `host`（精确域名，最高优先级）
    2. `host-suffix`（域名后缀）
    3. `host-keyword` / `host-wildcard`（关键字 / 通配符）
    4. `geoip` / `ip-cidr` / `ip6-cidr` / `ip-asn`（IP 类）
    5. `user-agent`
    6. `final`
  * 同类型规则内，本地 `[filter_local]` 优先于远程 `[filter_remote]`，远程按书写顺序生效。
  * **跨 Bundle 覆盖风险提示**：若靠后 Bundle（如 `direct_cn`）中存在精确 `host` 规则，而靠前 Bundle（如 `aigc` 或 `streaming`）中仅写了同域名的 `host-suffix`，在开启分流匹配优化时，靠后的精确 `host` 可能反超命中；因此关键例外（如 `cdn.jsdelivr.net`）在 QX 侧须留意类型层级，并在 `build-report.json` 中审计适配差异。
* **DNS 绑定机制与限制**：
  * **`[dns]` 不支持规则集绑定**，仅支持单域/通配写法 `server = /domain/upstream` 与 `doh-server = /domain/url`。代理命中流量默认远端解析，本地 `[dns]` 仅负责直连域名、Apple 系统域与机场节点引导。
* **不支持项与适配策略**：
  * **不支持**：`DOMAIN-REGEX`（仅白名单转 `host-wildcard` 或数字后缀枚举，标记 `QX-ADAPTED`）、`AND`/`OR`/`NOT`（不支持，编译期 fail-closed 报错）、`PROTOCOL`（无 STUN 协议分流）、`PROCESS-NAME`/`PROCESS-PATH`、`URL-REGEX`。
  * 所有跳过项必须在 `dist/build-report.json` 中显式计数并列出原因，绝不静默丢弃。

---

## 3. 通用编译器红线

1. **无损规范源**：`upstream/` 与 `custom/services/` 使用统一规范 YAML Schema（`zhbcn-rules/v1`），不含任何平台专属 `PROCESS-*` 规则。
2. **禁止静默丢弃**：遇到未登记规则类型或未审阅正则，编译器立即报错退出（exit 1）；已审阅的跳过/适配项全量输出至 `dist/build-report.json`。
3. **`no-resolve` 一致性**：所有支持 `no-resolve` 的客户端对 IP/ASN 规则强制规范 `no-resolve`（Mihomo/Stash 写在 `RULE-SET` 与 classical 行尾；Egern 写在文件顶层 `no_resolve: true`；Loon 写在条目行尾；Quantumult X 远程规则在 `opt-parser=false` 下保持原生三段式）。
4. **DNS 纯净度**：凡 `dns_bound: true` 的 Bundle，供 DNS 引用的产物严禁包含任何 IP/ASN/URL 规则，由 `scripts/check.py` 强制校验。
