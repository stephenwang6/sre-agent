# AI-Native SRE Agent

面向 NetBox（DCIM/IPAM）及其 Docker 承载环境的 AI 值班 Agent。以 Tool Calling 方式调用运维工具，自动完成：

**发现异常 → 诊断根因 → 最小影响处置 → 复核验证 → 汇总报告**

## 特点

- 标准 Tool Calling 协议，消息格式与 OpenAI function calling 一致
- 可插拔大脑：本地 SRE Runbook 策略，或任意 OpenAI 兼容 LLM
- 分级安全：read 直接执行，write / danger 需人工审批

## 快速开始

```bash
pip install -r requirements.txt
cp .env.example .env      # 填写 NETBOX_URL 和 NETBOX_TOKEN

python3 main.py all                    # 注入演示数据 + 跑完整闭环
python3 main.py all --approve-all      # 自动批准写操作（无人值守）
python3 main.py reset                  # 清理演示数据
```

命令：`seed` 注入演示拓扑与异常、`run` 只跑闭环、`all` 两者、`reset` 清理。
`--brain` 可选 `auto`（默认，有 Key 用 LLM）/ `local` / `llm`。

## 结构

| 文件 | 作用 |
|------|------|
| `main.py` | 命令行入口 |
| `sre_agent/runtime.py` | ReAct 主循环：think → tool_calls → observe |
| `sre_agent/tools.py` | 工具注册表（发现/诊断/处置），JSON Schema 描述 |
| `sre_agent/brain.py` | 决策大脑：LocalPolicyBrain / OpenAICompatibleBrain |
| `sre_agent/client.py` | NetBox REST API 客户端 |
| `scenarios/seed_topology.py` | 演示拓扑与异常注入 |

## 依赖对象

[netbox-docker](https://github.com/netbox-community/netbox-docker.git) 部署的 NetBox，及其 Docker 容器环境。
