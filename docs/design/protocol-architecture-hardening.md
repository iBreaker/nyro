# Nyro 协议转换架构定型（Architecture Hardening）

**Nyro Gateway · 架构设计文档**

---

## 1. 背景与目标

Nyro 在多协议入口（OpenAI / Anthropic / Gemini / Responses）与多厂商出口之间做转换。随着工具调用（tool calling）和推理内容（reasoning）场景增加，单纯字段映射会出现语义丢失和顺序错误问题。

本次架构定型目标：

- 建立语义保真的内部表示（IR），避免跨协议转换信息丢失
- 将 tool call / tool result 关联逻辑集中化，消除 2013 类顺序与 ID 错误
- 完整支持 Responses API item 级语义（reasoning / function_call / message）
- 统一流式与非流式行为，保证 finish_reason、usage、工具事件一致
- 为长期迭代提供稳定边界：新增厂商时优先复用语义层，不再在入口/出口散落修补

---

## 2. 设计原则

- **语义优先**：先还原语义，再做协议编码
- **单向分层**：Ingress Decoder -> Semantic Normalize -> Egress Encoder -> Formatter
- **最小耦合**：协议差异收敛在 `protocol/*`，业务编排留在 `proxy/handler`
- **可观测可回归**：关键行为必须有回归测试覆盖
- **严格但可诊断**：不做 silent fix，无法恢复时返回明确错误

---

## 3. 总体架构

```text
Ingress Request
  -> protocol/*/decoder
  -> InternalRequest (IR)
  -> semantic normalization
     - reasoning extraction
     - tool correlation
     - response items construction
  -> protocol/*/encoder (egress provider)
  -> upstream call
  -> protocol/*/stream parser or response parser
  -> InternalResponse / StreamDelta
  -> semantic post-process
  -> protocol/* formatter (to ingress protocol)
  -> Client
```

### 3.1 ASCII Art 调用流程图（完整链路）

```text
+--------------------+                  +----------------------------------------+
| Client / CLI / SDK | -- HTTP/SSE --> | Nyro Proxy Entry (axum route handler) |
+--------------------+                  +-------------------+--------------------+
                                                        |
                                                        v
                                     +------------------------------------------+
                                     | Ingress Decoder                          |
                                     | - openai/anthropic/gemini/responses      |
                                     | - parse request -> InternalRequest (IR)  |
                                     +-------------------+----------------------+
                                                         |
                                                         v
                                     +------------------------------------------+
                                     | Semantic Normalize (Request Side)        |
                                     | - reasoning extraction                   |
                                     | - tool correlation / id recovery         |
                                     | - response-items pre-shape (if needed)   |
                                     +-------------------+----------------------+
                                                         |
                                                         v
                                     +------------------------------------------+
                                     | Egress Encoder (Target Provider Protocol)|
                                     | - openai / anthropic / gemini            |
                                     | - sanitize schema / normalize tool ids   |
                                     +-------------------+----------------------+
                                                         |
                                                         v
                                     +------------------------------------------+
                                     | Upstream HTTP Call (reqwest)             |
                                     +-----------+------------------------------+
                                                 |
                           +---------------------+----------------------+
                           |                                            |
                           v                                            v
            +-------------------------------+            +----------------------------------+
            | Non-Stream Upstream Response  |            | Stream Upstream SSE Response     |
            +---------------+---------------+            +----------------+-----------------+
                            |                                             |
                            v                                             v
         +-------------------------------------------+   +-------------------------------------------+
         | Response Parser                           |   | Stream Parser                             |
         | -> InternalResponse                       |   | -> StreamDelta sequence                   |
         +----------------------+--------------------+   +----------------------+--------------------+
                                |                                           |
                                v                                           v
         +-------------------------------------------+   +-------------------------------------------+
         | Semantic Post-Process                     |   | Semantic Post-Process                     |
         | - reasoning/thinking normalize            |   | - reasoning delta normalize               |
         | - function_call/message item finalize     |   | - tool_call delta ordering fix            |
         +----------------------+--------------------+   +----------------------+--------------------+
                                |                                           |
                                v                                           v
         +-------------------------------------------+   +-------------------------------------------+
         | Formatter (to ingress protocol)           |   | Stream Formatter (to ingress protocol)    |
         | - finish_reason / usage align             |   | - SSE events + DONE / stop events         |
         +----------------------+--------------------+   +----------------------+--------------------+
                                |                                           |
                                +-------------------+-----------------------+
                                                    |
                                                    v
                                   +------------------------------------------+
                                   | Return to Client                         |
                                   | - JSON (non-stream) or SSE (stream)     |
                                   +------------------------------------------+

      Side Channel (async):
      +--------------------------------------------------------------+
      | usage/status/latency/tool flags -> logging & stats collector |
      +--------------------------------------------------------------+
```

核心收益：

- 对外协议数量继续增加时，只需扩展“协议适配层 + 语义映射点”
- 复杂工具链行为统一在语义层收敛，避免每个 provider 重写一遍规则

---

## 4. 核心模块设计

### 4.1 语义保真 IR

在 `crates/nyro-core/src/protocol/types.rs` 扩展内部结构：

- `InternalResponse` 支持推理内容与 item 级表达
- `StreamDelta` 支持 reasoning 增量事件，与 text/tool 并行
- 保持字段可选与默认值，尽量降低编译与调用面的破坏性

设计意图：将“协议字段”转换为“语义对象”，避免直接在 OpenAI/Anthropic/Gemini 字段间互转。

### 4.2 语义规范化层

目录：`crates/nyro-core/src/protocol/semantic/`

- `reasoning.rs`：统一提取 reasoning（结构化字段优先，必要时 `<think>` 兜底）
- `tool_correlation.rs`：统一 tool_call_id 关联与恢复（含 hint、重排、冲突处理）
- `response_items.rs`：统一构建 Responses item（reasoning/function_call/message）

这层是本次定型的核心，负责将“各厂商差异”转成“Nyro 内部语义一致性”。

### 4.3 协议适配层（Ingress / Egress）

按协议拆分在：

- `protocol/openai/*`
- `protocol/anthropic/*`
- `protocol/gemini/*`
- `protocol/openai/responses/*`

职责边界：

- **decoder**：协议输入 -> IR
- **encoder**：IR -> 上游协议请求
- **stream/parser/formatter**：流式事件与收尾语义对齐

### 4.4 Proxy 编排层

`crates/nyro-core/src/proxy/handler.rs` 负责串联流程：

- 入口解码
- 请求侧语义规范化（工具关联修复等）
- 目标协议编码并转发
- 响应侧语义抽取与回写
- 按入口协议格式化返回

---

## 5. 关键语义问题与落地策略

### 5.1 Tool Call 关联稳定性

目标：保证 `assistant(tool_call) -> tool(tool_result)` 在各链路都可恢复到合法序列。

策略：

- 优先按 `tool_call_id` 精确匹配
- 其次按工具名与上下文 hint 兜底
- 处理重复 ID、孤儿 tool_call、非相邻 tool_result 等场景
- 无法恢复时返回明确错误，不放行潜在错误请求

### 5.2 Responses API Item 级语义

目标：不再把 item 语义压扁成纯文本。

策略：

- non-stream：输出 `reasoning` / `function_call` / `message`
- stream：输出 item 级增量与收尾事件
- 解码侧支持 `input` 中工具与函数输出语义

### 5.3 Reasoning 与 `<think>` 兼容

目标：客户端不应看到原始 `<think>` 标签泄漏。

策略：

- parser 阶段提取 `<think>` 为 reasoning delta
- formatter 阶段按目标协议映射为标准 reasoning/thinking 结构
- 对不支持结构化推理的上游采用安全降级

### 5.4 Gemini / Anthropic 差异处理

- Gemini：工具参数 schema 做安全清洗，去除不兼容字段（如 `$schema` 等）
- Gemini stream：延迟 functionCall 输出，确保参数 JSON 完整
- Anthropic：工具 ID 规范化，保证 tool_use_id 合法

---

## 6. 流式与非流式一致性约束

统一约束：

- 存在 `tool_calls` 时，`finish_reason` 必须为 `tool_calls`
- usage 信息尽量映射到统一字段，别名键统一归一
- 空白文本块不应触发无意义输出
- 结束事件必须完整，避免 CLI 提前中断或挂起

---

## 7. 测试与验收

测试主文件：`crates/nyro-core/tests/protocol_conversion.rs`

覆盖重点：

- tool_call_id 关联、重排、去重、修复
- Responses item 语义完整性（含 streaming）
- Gemini schema 清洗与工具参数映射
- Anthropic thinking/tool id 合法性
- finish_reason 与工具调用一致性

验收目标（典型链路）：

- Claude Code -> Nyro -> MiniMax（OpenAI/Anthropic）稳定
- Codex -> `/v1/responses` 工具链可持续执行
- Gemini CLI / OpenCode 不再出现 tool result 顺序错误与 think 泄漏

---

## 8. 兼容性与演进策略

- 本次作为架构定型版本：后续尽量只做增量能力，不做大改层级
- 新增 provider 时优先复用 semantic 层，避免复制粘贴逻辑
- 若需 provider 特化行为，优先通过小而清晰的函数落在对应协议模块
- 所有行为调整需配套回归测试，确保长期可维护

---

## 9. 结论

本方案将 Nyro 协议转换从“字段级适配”升级为“语义级转换”。通过 IR + semantic normalization + 协议适配分层，Nyro 可以在保持现有入口/出口协议能力的同时，显著提升稳定性、可扩展性与可测试性，为后续长期迭代提供稳定架构基线。

