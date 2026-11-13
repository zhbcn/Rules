# Rules

个人代理分流规则库。

| 目录 | 用途 |
|---|---|
| `Ruleset/Mihomo/` | Clash Verge Rev / FlClash 维护源 |
| `Ruleset/Egern/` | Egern 原生维护源，与 Mihomo 配对 |
| `Ruleset/QuantumultX/` | 由 Mihomo 源生成；策略由客户端 `force-policy` 指定 |
| `Ruleset/Stash/` | 由 Mihomo 源按 domain / ipcidr / classical 顺序生成 |

## AI 规则如何分布

- `AI/<服务>.yaml` 按服务归属维护。中国站和可直连的全球站可放入同一服务集合；规则资源不决定出口。
- `AI/ChinaAI.yaml` 聚合国产 AI 的国内域名和已选择直连的全球域名，明确排除代理例外。上游的 `category-ai-cn` 是服务归属参考，不是所有登录、模型及地区功能可用的证明。
- `Direct/cn.yaml` 继续包含 ChinaAI 条目，为已有客户端 URL 提供兼容。新增独立服务资源发布前，配置可继续使用既有服务/cn 资源及少量本地规则，不引用未发布 URL。
- `*International` 资源保留旧路径兼容，不代表客户端必须代理。Qwen、智谱不再在自用配置中优先引用国际子集。MiniMax 采用综合集合，Talkie 以客户端更靠前的域名例外走 AIGC。
- ByteDanceAI 的 Coze、TRAE、Dola/Cici 全球子集暂保留代理；国内豆包、扣子、TRAE 直连。TRAE 国际服务的地区限制应以官方列表为准。Manus 等其他服务的既有策略不随公司出生地改变。
- 不把共享 CDN、整个云厂商域名或第三方登录/模型供应商并入某家国产 AI 的直连集合。

`AI/` 中新增 DeepSeek、Kimi、BaiduAI、TencentAI、Kling、Spark、Tiangong、Baichuan、Metaso、SenseNova、XiaomiAI 独立资源。完整的服务归属、选取的上游、保留 custom、代理例外及公开验证入口统一维护在 `scripts/ai_services.json`。

## NVIDIA 出口边界

`Technology/NVIDIA.yaml` 保留 V2Fly 综合范围和旧 URL 兼容，不应整体绑定 DIRECT。先匹配 `Technology/NVIDIA_Direct.yaml` 走 DIRECT，其余 NVIDIA 综合集合走 Public network，且两者都应先于广义国内/全球聚合；DNS 同步按直连子集使用国内公共解析、全球余集使用经 Public network 的全球解析。

直连子集仅合并两类同出口域名：V2Fly `nvidia` 的中国标记（nvidia.cn、geforce.cn、gputechconf.cn），以及驱动检查/下载（精确 gfwsl.geforce.com、services.gfe.nvidia.com 和 download.nvidia.com 后缀）。无需再拆成两个同策略资源。download 后缀涵盖 cn/us/uk/international 与 international-gfe 镜像，不把 nvidia.com 或 gfe.nvidia.com 整段直连；同一下载主机的其他文件也会直连。中国网页的全球 API、登录和第三方依赖仍按其自身域名匹配，不保证整页功能全直连。

依据：V2Fly [nvidia 清单](https://github.com/v2fly/domain-list-community/blob/cb663f66025ef3be1c1c7eb367dfac5f46645ffc/data/nvidia) 的 `@cn`；[NVIDIA 官方驱动页](https://www.nvidia.com/en-us/drivers/) 的 gfDriversServicesToolkitUrlEndpoint 指向 gfwsl.geforce.com；该主机 AjaxDriverService.php 的 DriverManualLookup 实际返回 uk.download.nvidia.com 驱动链接；services.gfe.nvidia.com 是 [NVIDIA 支持论坛记录](https://www.nvidia.com/en-us/geforce/forums/user/204701/) 中的旧 GFE 更新服务，仅作精确主机兼容，不等于已验证当前 NVIDIA App 全部端点。

www.nvidia.com 同时按 `/en-us/`、`/zh-cn/` 等路径承载网页，域名规则无法按语言或页面地区拆分。该主机统一归全球余集；www.nvidia.cn 及其中国域子站归直连。中国标记是可维护的归属依据，不等于中国大陆设备连通性实测。

新增 NVIDIA_Direct 四格式资源须另行授权发布。发布前，五份自用配置内嵌与该集合一致的六条原生例外，并沿用已发布 NVIDIA URL，因此无需提前采用任何新资源 URL；发布后可将本地镜像替换为该资源引用并保持同样优先级。不要仅更新远程旧资源就声称设备出口已变更，仍需采用新版私密配置并验证。

## 更新与检查

`sync_ai.py` 只读取指定的本地 V2Fly `data/` 快照，不主动联网，不读取订阅，也不修改客户端。它优先使用独立服务名单，聚合名单只按明确域名归属提取，保留现有 custom；删除旧条目需单独审查。源文件继续保留在原有路径。

```sh
python scripts/sync_ai.py --data '<V2Fly checkout>/data'
python scripts/sync_ai.py --data '<V2Fly checkout>/data' --check
python scripts/convert_quantumultx.py
python scripts/convert_stash.py
python -m unittest discover -s tests
python scripts/check.py
```

`check.py` 同时检查服务与 ChinaAI/cn 聚合是否一致、代理例外是否误入直连集合，以及四种资源的生成一致性。同步脚本本身不刷新上游；调用者应先取得并记录所用的上游版本。新增 Stash 组件或改变分型时，应先生成配置候选并发布资源，再采用候选。

客户端另用 `check.py --config <文件>` 检查；Stash 使用 `--stash-config`。私密配置、订阅、节点凭据和设备证据不放入本仓库。

## 直连探测与判断边界

`probe_ai_direct.py` 是手动运行的 Windows 工具。必须指定物理网卡索引和源 IPv4；它通过 `IP_UNICAST_IF` 约束 AliDNS DoH 与 HTTPS 请求，校验 TLS，拒绝环回、私网和 fake-IP DNS 答案，只跟随清单内入口的跳转。不会回退为未经绑定的请求，不会调用模型、携带密钥、刷新订阅或改变系统网络设置。输出到调用者指定的位置，不自动提交证据。

```sh
python scripts/probe_ai_direct.py --interface-index <物理网卡索引> --source-ip <物理IPv4> --output <私有证据目录>/ai-direct.json
# 可重复指定 --service，只检查部分服务
python scripts/probe_ai_direct.py --interface-index <索引> --source-ip <IPv4> --service Qwen --output <路径>/qwen.json
```

- HTTP 200/206：仅公开页面或下载入口可达。
- API 返回 401：已接通 API 服务器，鉴权及模型调用未验证。
- 403、DNS 异常、超时、无法完成的跳转：保留为未验证，不自动改策略。
- 一台设备、一个网络的结果不代表所有地区。主页可达不保证登录、支付、WebSocket、模型、媒体或第三方依赖可用。策略修改需要结合官方地区约束和实际业务验证。
