# Shadowrocket Policy

合并公开上游规则，生成带 `pre-matching` 的原生拒绝模块和国内直连规则。每日 10:23 UTC 自动更新。

## 使用

在 Shadowrocket「配置 → 模块 → +」导入隐私模块：

```text
https://raw.githubusercontent.com/cresseelia/shadowrocket-policy/main/generated/native-reject.module
```

模块名称为 `Shadowrocket Privacy Reject`。保留上述 GitHub 订阅地址，使用「更新模块」获取新版本；开启模块页「保存到 iCloud」可同步模块。GitHub 提供规则更新，iCloud 同步模块数据，两者分别负责不同用途。

广告合集使用兼容版 `Shadowrocket Adblock`，替代原“全部-广告拦截合集”：

```text
https://raw.githubusercontent.com/cresseelia/shadowrocket-policy/main/generated/adblock.module
```

主配置关闭 HTTPS/SVCB DNS 查询转发，并引用国内规则集（合并到已有段落）：

```ini
[General]
allow-dns-svcb = false

[Rule]
RULE-SET,https://raw.githubusercontent.com/cresseelia/shadowrocket-policy/main/generated/direct.list,DIRECT
```

主配置继续保留自己的节点、自建 DNS、特殊分流和最终策略。正式隐私模块只包含拒绝规则，不修改全局 DNS 设置。全量模块已在手机加载，DNS 抽样对照通过；具体 App 功能仍需逐项验证。启用后停用被替代的 GMO reject/direct 模块和重复拒绝引用，GMO 数据仍作为上游每日合并。

“墨鱼去开屏 2.0”继续使用 ddgksf2013 的原订阅及现有 Script Hub 转换；证书、Plugin2Rocket、HTTPDNS、广告平台及实际需要的小红书/彩云/DiDiClean 专项模块按需保留。广告合集原版停用，由本站兼容版替代，避免重复加载。

## 来源与改动

| 输出 | 上游来源 | 本站改动 |
| --- | --- | --- |
| `direct.list` | [blackmatrix7 ChinaMaxNoIP](https://github.com/blackmatrix7/ios_rule_script/tree/master/rule/Shadowrocket/ChinaMaxNoIP) 的 Domain/list 两表；[GMOogway direct](https://github.com/GMOogway/shadowrocket-rules/blob/master/sr_direct_list.module) | 合并、去重，移除内嵌 DIRECT 策略，由主配置引用时指定；保留域名类型、匹配选项和其他分流规则。 |
| `native-reject.module` | [Vincent-Loeng reject](https://github.com/Vincent-Loeng/shadowrocket-rules/blob/release/reject.list)、[GMOogway reject](https://github.com/GMOogway/shadowrocket-rules/blob/master/sr_reject_list.module)，补充[可莉广告平台](https://kelee.one/Tool/Loon/Lpx/BlockAdvertisers.lpx)和[HTTPDNS](https://kelee.one/Tool/Loon/Lpx/Block_HTTPDNS.lpx)的纯域名拒绝 | 合并、去重，在实际 DOMAIN/DOMAIN-SUFFIX 规则上加 `REJECT,pre-matching`；不把 URL 路径规则扩大为整域拒绝。与明确例外重叠的范围退出提前拒绝。 |
| `adblock.module` | [zirawell/R-Store 全部广告合集](https://github.com/zirawell/R-Store/blob/main/Rule/Surge/Adblock/All/allAdBlock.sgmodule) | 移除把 `ios.chat.openai.com/public-api/mobile/app_support_status` 替换为 `{}` 的 Map Local 规则，恢复真实接口响应；修改显示名称和订阅地址，保留原作者署名及其余规则、改写、脚本和顺序。 |

以上产物每日从对应上游重新生成；上游未再包含该 ChatGPT 改写时不额外处理，若其形式或语义改变则停止发布并等待核对。

兼容版目前只修正已确认的 ChatGPT 空响应误伤。美团 `layout.meituan.net` 整域拒绝及 `travelcube` 图片改写仍沿用上游，尚待业务对照验证。

## 维护

Python 3.11+，不需要额外依赖：

```sh
python3 -m unittest -v
python3 generate.py
```

`sources.toml` 管理上游和覆盖检查；`corrections.toml` 登记经确认的例外。例外只退出提前拒绝，已有连接规则仍需相应修正。`reject-deferred.list` 非空时，在具体正常路由之后引用并指定 REJECT。`manifest.json` 记录来源哈希、更新状态和数量。

下载或校验失败不发布新结果。部分上游不可用时使用有期限的快照，过期停止更新。各上游许可与署名要求继续适用，广告合集保留 zirawell 的作者与主页信息。

仅公开规则与生成工具，私有配置放在已忽略的 `private/`。
