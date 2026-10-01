# Sentinel 核验与证据原型

这是独立的**开发原型**，用于和社区情报模块对齐接口。2026-10-01 核对时团队仓库的 `main` 分支只有 README，尚无既定代码技术栈，因此这里使用 Node.js 20 标准库，不依赖数据库服务或第三方包。当前只演示一种事件：**可疑合约报告**。所有报告和证据均由人提交，核验结论由指定审核者手动做出。可选的只读 RPC 检查能查询交易与收据，但**不能判定合约是否恶意**。待团队确认核验规则、社区接口及通知渠道后再集成。

## 已实现的闭环

```text
提交报告与证据 → submitted / informational
              → in_review / under_investigation（可补充证据）
              → verified / credible_threat 或 confirmed_incident
              → rejected（不公开）
verified → corrected（可调整公开级别）→ retracted
```

- 每份报告有 UUID、链 ID、合约地址、标题、描述、提交者、时间戳，以及 1–10 条证据。
- 证据支持交易哈希和公开 HTTPS 来源；来源链接不能携带凭据、查询参数或片段。输入会检查格式，但**不会自动判断来源可信度或交易含义**。
- 审核者必须记录不少于 20 字符的理由；核验通过时还须给出用户行动建议。提交者不能审核自己的报告。
- 调查中，指定审核者可补充证据；每条证据记录添加者。核验发布时必须手动选择“可信威胁”或“已确认事件”。这两个级别是团队 README 中的方向，具体判定标准尚待团队敲定。
- 公开告警列表只包含 `verified`。被驳回或尚在审核的报告仅在审核接口中可见。
- 公开告警会去掉提交者与证据添加者标识；完整来源责任记录只在审核接口中可见。
- 审核者发布时必须逐条选择可公开的证据；未选中的原始证据和对应链上观察不进入公开告警。
- 公开概览显示当前告警数及分级数；已发布事件历史含更正和撤回。撤回后告警不再出现在活动列表，但原告警 ID 仍可查询撤回状态和理由。
- 审核中可选择查询配置好的链上 RPC：先核对链 ID，再查询交易与收据，记录交易是否直接指向报告合约、是否上链及执行状态。观察结果不会自动改变审核状态。
- 审核者可维护基本地址监看列表，手动查询目标合约最近 100 个区块发出的事件日志。该观察不运行后台轮询，也不产生自动风险结论。
- 发布、更正和撤回会生成本地通知草稿事件，供社区侧后续对接；**不会发送到 Telegram、Discord 或用户**。
- 审核者可查看按自报 `reporterId` 汇总的报告、发布、驳回与待处理数量；它不是实名身份或信誉评分。
- 本地文件以原子替换方式保存；运行时对修改排队，防止同一进程内的并发写入相互覆盖。

## 运行

需要 Node.js 20 或更新版本，无需 `npm install`。

```bash
cd prototype
npm test
npm run demo
```

启动本地 HTTP API：

```bash
cd prototype
export REVIEWER_ID=demo-reviewer
export REVIEWER_TOKEN="$(openssl rand -hex 32)"
npm start
```

启动后打开 `http://127.0.0.1:8787/`，即可在页面中提交报告、审核、查看告警及更正/撤回。点击“填入演示数据”可使用虚构地址和交易哈希。页面使用同一套 HTTP 接口，没有单独的前端服务。

默认只监听 `127.0.0.1:8787`。可通过 `PORT` 和 `DATA_FILE` 指定端口与存储文件；默认数据存于 `prototype/data/sentinel.json`。请保护 `REVIEWER_TOKEN` 和数据文件，不要将它们提交到仓库。

如需启用链上只读检查，在启动前设置 `RPC_URL` 为所用 Monad 网络的 HTTPS RPC 地址（本机 RPC 可以使用 loopback HTTP）。RPC 地址仅由服务器配置，提交报告的人不能指定。报告的 `chainId` 必须与 RPC 返回的链 ID 相同。原型不会发送链上交易；RPC 提供商会收到所查询的交易哈希。

例如，使用测试网演示数据时可在 `npm start` 前设置 `export RPC_URL=https://testnet-rpc.monad.xyz`。2026-09-28 实测该端点返回链 ID `10143`；主网公开端点 `https://rpc.monad.xyz` 返回 `143`，与 [Monad Developers 官方资料](https://github.com/monad-developers)一致。演示中的全 `a` 交易哈希在两个网络都返回 `not_found`，这是预期的虚构数据结果。

## 接口草案

| 方法 | 路径 | 访问 | 用途 |
| --- | --- | --- | --- |
| `POST` | `/v1/reports` | 公开 | 提交可疑合约报告与初始证据 |
| `GET` | `/v1/alerts` | 公开 | 读取当前已核验告警 |
| `GET` | `/v1/alerts/:id` | 公开 | 读取已发布告警，包括后续撤回状态 |
| `GET` | `/v1/reports` | 审核者 | 列出所有报告与审核记录 |
| `GET` | `/v1/reports/:id` | 审核者 | 查看单份报告 |
| `POST` | `/v1/reports/:id/review` | 审核者 | 开始审核 |
| `POST` | `/v1/reports/:id/evidence` | 审核者 | 调查中补充证据 |
| `POST` | `/v1/reports/:id/check-evidence` | 审核者 | 在审核中查询交易证据并记录只读 RPC 观察；需配置 `RPC_URL` |
| `POST` | `/v1/reports/:id/decision` | 审核者 | `verified` 或 `rejected`，附理由；核验通过时选择公开级别 |
| `POST` | `/v1/reports/:id/correction` | 审核者 | 更正已发布标题、建议或级别，附理由 |
| `POST` | `/v1/reports/:id/retraction` | 审核者 | 撤回已发布告警，附理由 |
| `GET` | `/v1/dashboard` | 公开 | 当前公开事件数量概览；不是安全评分 |
| `GET` | `/v1/alerts/history` | 公开 | 已发布事件历史，包括已撤回告警 |
| `GET` | `/v1/watchlist`、`POST /v1/watchlist` | 审核者 | 查看、添加地址监看目标 |
| `POST` | `/v1/watchlist/:id/check` | 审核者 | 手动查询近 100 个区块的事件日志 |
| `POST` | `/v1/watchlist/:id/archive` | 审核者 | 保留记录并归档监看目标 |
| `GET` | `/v1/notifications/outbox` | 审核者 | 查看未发送的通知草稿事件 |
| `GET` | `/v1/contributors` | 审核者 | 查看自报提交者的数量统计，不做信誉排名 |

审核接口使用 `Authorization: Bearer <REVIEWER_TOKEN>`。审核者身份由服务器的 `REVIEWER_ID` 指定，不接受请求自行指定。请求和响应均为 JSON；错误返回 `{ "error": "...", "message": "..." }`。

完整的机器可读接口草案在 [openapi.json](openapi.json)，启动服务后也可从 `/openapi.json` 读取。此接口仍需与团队协商，不代表正式版本。

提交报告示例：

```json
{
  "reporterId": "community-member",
  "chainId": 10143,
  "contractAddress": "0x1111111111111111111111111111111111111111",
  "title": "Demo: suspicious contract activity",
  "description": "A fictional report for testing the review workflow; no real contract is accused.",
  "evidence": [
    {
      "kind": "transaction",
      "txHash": "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "note": "Fictional transaction hash used only in the local demonstration."
    }
  ]
}
```

审核决策示例：

```json
{
  "outcome": "verified",
  "classification": "credible_threat",
  "reason": "The reviewer checked the submitted evidence and documented why the report should be published.",
  "advice": "Avoid interacting with this contract until the incident is clarified.",
  "publicEvidenceIds": ["<从报告审核接口取得的证据 UUID>"]
}
```

公开来源证据格式：`{ "kind": "public_source", "url": "https://example.org/notice", "note": "说明来源与事件的关系" }`。更正请求包含 `title`、`advice`、`reason`，可选 `classification`；撤回请求包含 `reason`。

## 技术选择和边界

此版本把[业务规则](src/core.mjs)、[文件存储](src/store.mjs)、[只读 RPC 适配层](src/rpc.mjs)和 [HTTP 适配层](src/server.mjs)分开。获得团队仓库后，可以保留状态规则和接口语义，按现有技术栈替换 HTTP 或存储实现。

上线前仍需团队确定核验标准、审核角色与权限、社区侧字段和告警渠道、Monad 网络范围，以及是否有必要上链。当前的共享审核令牌和自行填写的提交者 ID 只适合本机演示；单文件存储仅支持一个服务进程。没有自动信誉评分、证据抓取、去重、后台监控、真实通知分发、链上写入或生产级身份认证。HTTP 全流程已在 localhost 验证；RPC 已在 Monad 主网和测试网用虚构哈希走通只读交易查询，测试网的虚构地址也完成近 100 区块日志查询，尚未用真实事件证据进行分析。交易成功、目标地址吻合、日志数量或人工标记 `verified` 都不等于合约安全保证。
