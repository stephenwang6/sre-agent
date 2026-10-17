# AI-Native SRE Agent（NetBox Tool-Calling 闭环）

一个真正具备 **Tool Calling 结构**的 SRE 值班 Agent，以 [netbox-docker](https://github.com/netbox-community/netbox-docker.git)
部署的 NetBox（DCIM/IPAM）及其 Docker 承载环境为运维对象，完成完整闭环：

> **发现异常 -> 诊断根因 -> 最小影响处置 -> 复核验证 -> 汇总报告**

## 架构

```
                 +---------------------------------------------+
                 |              AgentRuntime                    |
                 |         （ReAct 风格主循环）                  |
                 |  think -> tool_calls -> observe -> ...       |
                 +---------------------------------------------+
                     |                          ^
            tool_schemas()                 消息历史(messages)
                     v                          |
        +--------------------+        +-----------------------+
        |   Brain（可插拔）   |        |   ToolExecutor        |
        |--------------------|        |  read    -> 直接执行   |
        | LocalPolicyBrain   |        |  write   -> 人工审批   |
        |  (本地 SRE Runbook) |        |  danger  -> 人工审批   |
        | OpenAICompatible   |        +-----------------------+
        |  Brain (任意 LLM)   |                 |
        +--------------------+                 v
                              +-------------------------------+
                              |         Tool Registry         |
                              |  11 个工具，JSON Schema 描述   |
                              |  发现 / 诊断 / 处置 三类        |
                              +-------------------------------+
                                         |
              +--------------------------+--------------------------+
              v                          v                          v
     NetBox REST API            Docker CLI               NetBox 日志(Journal)
```

## Tool Calling 协议

工具定义与消息格式和 **OpenAI function calling 完全一致**：

```python
# 工具定义（tools 列表）
{
  "type": "function",
  "function": {
    "name": "netbox_scan_ip_conflicts",
    "description": "IPAM 冲突扫描：a) 重复 IP 分配；b) 同站点/VRF 下重叠前缀...",
    "parameters": {"type": "object", "properties": {}, ...}
  }
}

# 决策（assistant 消息）
{"role": "assistant", "tool_calls": [{"id": "s1_c0", "type": "function",
   "function": {"name": "netbox_delete_object", "arguments": "{\"object_type\": \"prefixes\", \"id\": 6}"}}]}

# 观察（tool 消息）
{"role": "tool", "tool_call_id": "s1_c0", "name": "netbox_delete_object", "content": "{\"ok\": true, ...}"}
```

## 工具清单（11 个）

| 阶段 | 工具 | 安全等级 | 说明 |
|------|------|----------|------|
| 发现 | `netbox_service_health` | read | NetBox 版本 / RQ worker 健康 |
| 发现 | `netbox_scan_ip_conflicts` | read | 重复 IP 分配 + 同范围重叠前缀检测 |
| 发现 | `netbox_scan_status_consistency` | read | planned 但已部署 / 下线设备残留活跃 IP |
| 发现 | `docker_container_status` | read | netbox-docker 栈容器健康 |
| 诊断 | `netbox_get_object` | read | 任意对象详情（白名单类型） |
| 诊断 | `netbox_get_ip_assignments` | read | IP 全部占用点 + 设备状态 |
| 诊断 | `netbox_get_device_context` | read | 设备上下文（接口/IP/线缆/历史日志） |
| 处置 | `netbox_update_object` | write | PATCH 更新（如设备状态修正） |
| 处置 | `netbox_delete_object` | dangerous | DELETE（仅限 ip/interfaces/cables/prefixes） |
| 处置 | `netbox_add_journal_entry` | write | 写 NetBox 日志形成审计闭环 |
| 处置 | `docker_restart_container` | dangerous | 重启容器（仅 netbox-docker-*，需审批） |

## 大脑（Brain）可插拔

- **LocalPolicyBrain**（默认）：内置 SRE 巡检 Runbook 的确定性策略大脑。
  它不是硬编码脚本——每一步都基于消息历史中**真实返回的工具结果**做条件决策
  （例如：只有扫描证据能明确区分"在网占用点"与"陈旧占用点"时才自动删除，
  否则转人工研判）。
- **OpenAICompatibleBrain**：设置 LLM Key 后自动切换，走与本地大脑完全相同的
  tool-calling 协议，支持 DeepSeek / Qwen / Moonshot / OpenAI 等任何
  OpenAI 兼容 API。

切换方式（编辑 `.env`）：

```bash
SRE_LLM_BASE_URL=https://api.deepseek.com/v1
SRE_LLM_API_KEY=sk-xxxx
SRE_LLM_MODEL=deepseek-chat
```

## 安全模型

1. **分级**：每个工具有 `read` / `write` / `dangerous` 等级；
2. **审批**：write/dangerous 执行前必须经过 `approval_callback`
   （CLI 默认交互询问，`--approve-all` 自动批准）；
3. **白名单**：对象类型、可删除类型、journal 目标类型均有白名单；
4. **证据红线**：没有明确证据（设备状态判定）不得删除；删除动作全部留痕
   （NetBox Journal + 本地执行轨迹报告）。

## 运行

```bash
pip install -r requirements.txt

# 完整演示：注入拓扑与异常 -> Agent 全闭环（自动批准写操作）
python3 main.py all --approve-all

# 分步
python3 main.py seed    # 只注入演示数据
python3 main.py run     # 只跑 Agent 闭环
python3 main.py reset   # 清理演示数据

# 交互审批（每个写操作询问 y/N）
python3 main.py run

# 强制使用本地策略大脑 / LLM 大脑
python3 main.py run --brain local
python3 main.py run --brain llm
```

## 演示场景与闭环实录

`scenarios/seed_topology.py` 在 NetBox 中搭建站点 `bj-a-dc`（2 机柜 / 5 设备 /
10 接口 / 4 IP / 4 线缆），并注入三类异常：

- **A1 前缀重叠**：`10.20.30.128/25` 误建于业务网段 `10.20.30.0/24` 之内；
- **A2 陈旧分配**：已下线设备 `old-server-05` 仍持有活跃 IP `10.20.30.40/24`，
  且残留一条连接到网交换机的线缆；
- **A3 状态不一致**：`branch-ap-07` 状态为 `planned`，但实际已布线并持有活跃 IP。

一次完整闭环的工具调用序列（来自 `reports/` 实录）：

```
step 1  发现：service_health / scan_ip_conflicts(1 冲突) / scan_status_consistency(2 异常) / docker_container_status
step 2  诊断：get_object(prefixes x2) / get_device_context(branch-ap-07) / get_device_context(old-server-05)
step 3  处置：[审批] delete prefixes#6 / update devices#15 status=active / delete ip-addresses#7 / delete cables#6
step 4  审计：add_journal_entry x3（父网段 + 2 设备）
step 5  复核：scan_ip_conflicts(0) / scan_status_consistency(0)
step 6  汇总：生成中文闭环报告 -> reports/sre_report_<时间戳>.md
```

每次运行会在 `reports/` 下落盘两份内容：完整工具调用轨迹 + 结构化闭环报告
（发现 / 诊断 / 处置 / 复核 / 遗留）。

## 目录结构

```
.
├── main.py                     # CLI 入口（seed / run / reset / all）
├── .env                        # NetBox 地址与 Token（LLM Key 也在这里）
├── requirements.txt
├── sre_agent/
│   ├── config.py               # 环境变量配置
│   ├── client.py               # NetBox REST 客户端（分页/错误处理）
│   ├── tools.py                # 11 个工具：Schema + 实现 + 安全分级
│   ├── brain.py                # 本地策略大脑 + OpenAI 兼容 LLM 大脑
│   └── runtime.py              # Tool-Calling 主循环 + 执行器 + 报告
├── scenarios/
│   └── seed_topology.py        # 演示拓扑与异常注入 / 清理
└── reports/                    # 运行报告（轨迹 + 闭环报告）
```

## 环境说明

- NetBox v4.7（netboxcommunity/netbox:v4.7-5.1.1），API Token 为 v2 格式
  （`Bearer nbt_<key>.<token>`，通过容器内 `manage.py shell` 创建）；
- 该版本设备状态使用 `decommissioning`，前缀归属使用 `scope_type/scope_id`，
  接口连线状态通过 `cable/connected_endpoints` 判断（均已适配）；
- Python >= 3.10，唯一第三方依赖 `requests`。
