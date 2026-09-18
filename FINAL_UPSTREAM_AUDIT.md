# 最终上游补全审计报告（第三轮）

审计日期：2026-09-19

## 这一轮做了什么

第二轮检查时只看两个上游项目里有没有“独立服务文件”（例如 V2Fly 有没有单独的 `data/coinbase` 文件）。但真正的原则是：只要在整个上游项目里能找到明确属于这个服务的规则，就应该拿来比较。因此这一轮把搜索范围扩大到了：

- V2Fly 的大类聚合文件（如 `category-cryptocurrency`、`category-ai-cn`、`category-ai-!cn`）和公司级聚合文件（如 `alibaba`、`telegram`、`binance`、`vercel`、`ethereum`、`category-porn`）；
- blackmatrix7 的聚合规则（如 `rule/Clash/Crypto/Crypto.yaml`）。

本轮只从聚合文件中挑“明确属于该服务”的域名补进来，没有把整类规则搬进来，也没有扩大任何规则的用途（例如 Shopping 规则只补购物域名，不补集团其他业务）。本轮没有修改任何客户端配置、DNS、TUN、节点或订阅。

使用的上游快照：

- v2fly/domain-list-community：`6fe5416797ec88d29a3a1c69ce1431d73b955e88`
- blackmatrix7/ios_rule_script：`aa137cf64cda1474352875cc7e01b6f7d087cc0d`

## 总体数字

- 检查的自维护（custom）规则：**63 个**（全部复查完毕）
- V2Fly 独立服务文件找到：0 个（第二轮已找到 6 个，本轮无新增）
- V2Fly aggregate/category 找到：**19 个规则**
- blackmatrix7 独立规则找到：0 个（第二轮已确认）
- blackmatrix7 aggregate 找到：**7 个规则**（其中 Etherscan、Uniswap 同时被 V2Fly 命中；Avalanche、Blockchair、Solana、Tether、TRONSCAN 仅 blackmatrix7 命中）
- 上游有命中、内容实际补充：8 个规则（Mihomo 与 Egern 各补 14 条域名）
- 上游有命中、内容无需变动、只修正来源注释：16 个规则
- 合计本轮修改 24 个规则 × Mihomo/Egern 双格式 = 48 个文件
- 两个上游完全找不到、仍为纯自维护：**39 个**

## 内容实际发生变化的规则（8 个）

每个规则都同时更新了 `Ruleset/Mihomo/` 和 `Ruleset/Egern/` 两个版本。

### AntAfu（原 1 条 → 新 2 条）
- 新增：`antaq.com`
- 来源：V2Fly `category-ai-cn`

### MiniMax（原 6 条 → 新 7 条）
- 新增：`xingyeai.com`
- 来源：V2Fly `category-ai-cn` / `category-ai-!cn`

### Qwen（原 3 条 → 新 6 条）
- 新增：`qianwen.aliyun.com`、`qianwen.com`、`qianwenai.com`
- 来源：V2Fly `category-ai-cn`

### Zhipu（原 6 条 → 新 7 条）
- 新增：`zhipucn.com`
- 来源：V2Fly `category-ai-cn`

### AliExpress（原 3 条 → 新 7 条）
- 新增：`ae-rus.net`、`aedns.ru`、`aeplatform.ru`、`aestatic.net`
- 来源：V2Fly `alibaba` 聚合
- 说明：这些是 AliExpress 专用加速/平台域名，不是阿里巴巴集团其他业务，没有扩大 scope。

### TON（原 1 条 → 新 2 条）
- 新增：`toncenter.com`
- 来源：V2Fly `telegram` 聚合

### Etherscan（原 6 条 → 新 7 条）
- 新增：`etherscan.com`
- 来源：V2Fly `ethereum` 聚合 + blackmatrix7 Crypto 聚合
- 说明：原有 `bscscan.com`、`polygonscan.com`、`arbiscan.io`、`basescan.org`、`snowtrace.io` 等浏览器全部保留。

### MEXC（原 5 条 → 新 7 条）
- 新增：`mexc.co`、`mexcsensors.com`
- 来源：V2Fly `category-cryptocurrency`
- 说明：原有 `images/public/static.mocortech.com`、`mexcdevelop.github.io` 全部保留。

## 只修正了来源注释、内容不变的规则（16 个）

这些规则的现有内容与上游命中部分完全重复，或现有内容比上游更完整，因此不增删条目，只把 `# SOURCE:` 注释改准确：

| 规则 | 上游命中 | 说明 |
| --- | --- | --- |
| HermesAgent | V2Fly `vercel` 聚合（skills.sh） | 内容保留 |
| Lazada | V2Fly `alibaba` 聚合（Lazada 子集） | 内容保留 |
| Hanime1 | V2Fly `category-porn`（hanime1.me） | 内容保留 |
| Bitcoin | V2Fly `category-cryptocurrency` | 内容保留 |
| Bitget | V2Fly `category-cryptocurrency`（bitget.com） | 内容保留 |
| BNBChain | V2Fly `binance` 聚合 | 内容保留 |
| Coinbase | V2Fly `category-cryptocurrency`（coinbase.com） | `asset-metadata-service-production.s3.amazonaws.com` 保留 |
| CryptoCom | V2Fly `category-cryptocurrency` | 内容保留 |
| Dogecoin | V2Fly `category-cryptocurrency` | 内容保留 |
| Hyperliquid | V2Fly `category-cryptocurrency`（hyperliquid.xyz） | 内容保留 |
| Uniswap | V2Fly `category-cryptocurrency`（uniswap.org）+ blackmatrix7 Crypto | 内容保留 |
| Avalanche | blackmatrix7 Crypto 聚合 | 内容保留 |
| Blockchair | blackmatrix7 Crypto 聚合（blockchair.com） | 内容保留 |
| Solana | blackmatrix7 Crypto 聚合（solana.com） | 原有 `solana.org` 保留 |
| Tether | blackmatrix7 Crypto 聚合（tether.to） | 内容保留 |
| TRONSCAN | blackmatrix7 Crypto 聚合（tronscan.org） | 原有合理补充保留 |

## 仍为纯自维护的规则（39 个）

以下规则在 V2Fly 和 blackmatrix7 的独立文件与聚合文件中都找不到属于该服务的内容，继续由本仓库自维护：

- Crypto（26 个）：Aptos、AptosExplorer、BitcoinCash、Blockscout、Cardano、Chainlink、EtherFi、Krak、Mempool、Monero、NEAR、PokePay、Polkadot、Polygon、SAVO、Solscan、Starryblu、Stellar、Sui、SuiScan、TONViewer、TRON、USDC、XRPL、XRPScan、Zcash
- Shopping（12 个）：Allegro、ASOS、Etsy、Flipkart、iHerb、MercadoLibre、Mercari、Noon、SHEIN、Temu、Wayfair、Zalando
- Productivity（1 个）：Raindrop

## 验证结果

1. Python 单元测试：6 个全部通过。
2. `scripts/check.py`：402 个规则文件（Mihomo 201 + Egern 201）全部 YAML 可解析、无重复条目；4 份当前客户端配置（Clash Party、Egern、Ash-FlClash、吹雪-FlClash）引用的本仓库 URL 全部存在。`D:\dev\配置文件\FlClash.yaml` 是重构前的旧配置（仍引用第一轮已废弃的 Blockchain/Finance 旧路径），与本次修改无关，不属于验证范围。
3. Mihomo ↔ Egern 配对一致性：201 对文件逐一比对。本轮修改的 24 对（AI 5、Crypto 16、Shopping 2、Entertainment 1）语义完全一致。其余规则存在两处上游已知的表达方式差异（Mihomo 保留 PROCESS-NAME 规则、Egern 用 ASN 替代部分 IP 段），属第一轮重构时的既定取舍，不是本轮引入的问题。
4. `git diff --check`：无空白错误。
5. 客户端配置：0 个文件改动（本轮未触碰 `D:\dev\配置文件` 下任何文件）。

## 结论

63 个原自维护规则全部复查完毕：24 个在上游（含聚合文件）找到了属于该服务的成熟规则，其中 8 个补入了 14 条缺失域名；39 个确认为纯自维护。没有用上游聚合文件扩大任何规则的既定用途，所有 custom 中比上游完整的内容均已保留。
