"""运行时：Tool-Calling 主循环（ReAct 风格）与工具执行器。

消息协议与 OpenAI function calling 完全一致：
  assistant: {"role": "assistant", "tool_calls": [{"id", "type": "function",
              "function": {"name", "arguments": "<json>"}}]}
  tool:      {"role": "tool", "tool_call_id", "name", "content": "<json>"}

安全模型：write / dangerous 工具执行前必须通过 approval_callback 审批。
"""
from __future__ import annotations

import json
import os
from datetime import datetime

from .brain import BrainDecision, ToolCall
from .tools import READ, ToolContext, get_tool, tool_schemas

SYSTEM_PROMPT = (
    "你是 AI-Native SRE 值班 Agent，运维对象是 NetBox（DCIM/IPAM）及其 Docker 承载环境。"
    "你只能通过工具调用获取信息和执行动作，禁止臆测数据。"
    "闭环要求：发现异常 -> 诊断根因 -> 最小影响处置 -> 复核验证 -> 汇总报告。"
)


class ToolExecutor:
    """执行 tool_call：查表 -> 安全等级校验 -> 审批 -> 执行。"""

    def __init__(self, ctx: ToolContext, approval_callback=None):
        self.ctx = ctx
        self.approval_callback = approval_callback

    def execute(self, call: ToolCall) -> dict:
        tool = get_tool(call.name)
        if tool is None:
            return {"ok": False, "error": "未知工具: " + str(call.name)}
        if tool.safety != READ:
            if self.approval_callback is None:
                return {"ok": False, "rejected": True,
                        "error": "写操作未配置审批回调，已阻止"}
            proposal = {"tool": call.name, "safety": tool.safety, "arguments": call.arguments}
            try:
                approved = bool(self.approval_callback(proposal))
            except Exception as e:  # noqa: BLE001
                approved = False
                return {"ok": False, "rejected": True, "error": "审批失败: %s" % e}
            if not approved:
                return {"ok": False, "rejected": True, "error": "操作未获批准，已跳过"}
        try:
            return tool.handler(call.arguments, self.ctx)
        except Exception as e:  # noqa: BLE001
            return {"ok": False, "error": "%s: %s" % (type(e).__name__, e)}


def summarize(name: str, result: dict) -> str:
    """把工具结果压缩成一行可读摘要（用于控制台 trace）。"""
    if not isinstance(result, dict):
        return str(result)[:120]
    if not result.get("ok"):
        return "失败: " + str(result.get("error"))[:120]
    if name == "netbox_service_health":
        return "netbox v%s, rq_workers=%s" % (result.get("netbox_version"), result.get("rq_workers_running"))
    if name == "netbox_scan_ip_conflicts":
        return "扫描 %s 个前缀 / %s 个 IP，发现 %s 个冲突" % (
            result.get("scanned_prefixes"), result.get("scanned_ips"), result.get("conflict_count"))
    if name == "netbox_scan_status_consistency":
        return "扫描 %s 台设备，发现 %s 个一致性异常" % (result.get("scanned_devices"), result.get("anomaly_count"))
    if name == "docker_container_status":
        return "%s 个容器运行中，异常 %s 个" % (len(result.get("containers") or []), len(result.get("unhealthy") or []))
    if name == "netbox_get_object":
        obj = result.get("object") or {}
        return "%s#%s %s" % (obj.get("url", "").rstrip("/").split("/")[-2] if obj.get("url") else "?",
                             obj.get("id"), obj.get("display"))
    if name == "netbox_get_ip_assignments":
        return "%s 个占用点" % result.get("count")
    if name == "netbox_get_device_context":
        d = result.get("device") or {}
        return "设备 %s (%s): %s 接口 / %s IP / %s 线缆 / %s 日志" % (
            d.get("name"), d.get("status"), len(result.get("interfaces") or []),
            len(result.get("ip_addresses") or []), len(result.get("cables") or []),
            len(result.get("journal_entries") or []))
    if name == "netbox_update_object":
        return "更新 %s#%s -> %s" % (result.get("object_type"), result.get("id"), (result.get("result") or {}).get("display"))
    if name == "netbox_delete_object":
        return "删除 %s#%s" % (result.get("object_type"), result.get("id"))
    if name == "netbox_add_journal_entry":
        return "写入日志 #%s (%s)" % (result.get("entry_id"), result.get("kind"))
    if name == "docker_restart_container":
        return "重启 %s" % result.get("container")
    return "ok"


class AgentRuntime:
    """Tool-Calling 主循环：think -> tool_calls -> observe -> ... -> final。"""

    def __init__(self, brain, executor: ToolExecutor, max_steps: int = 25,
                 log=None, report_dir: str = "reports"):
        self.brain = brain
        self.executor = executor
        self.max_steps = max_steps
        self.log = log or (lambda msg: print(msg, flush=True))
        self.report_dir = report_dir
        self.events = []

    # ------------------------------------------------------------------ 主循环
    def run(self, task: str) -> str:
        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": task},
        ]
        self._event("task", task)
        self.log("=" * 72)
        self.log("Agent 启动 | 大脑: %s | 工具数: %d" % (self.brain.name, len(tool_schemas())))
        self.log("任务: " + task)
        self.log("=" * 72)

        final_content = ""
        for step in range(1, self.max_steps + 1):
            try:
                decision = self.brain.decide(messages, tool_schemas())
            except Exception as e:  # noqa: BLE001
                final_content = "[Agent] 大脑决策失败: %s" % e
                self.log("[step %d] 决策失败: %s" % (step, e))
                break

            if not decision.tool_calls:
                messages.append({"role": "assistant", "content": decision.content})
                final_content = decision.content
                self.log("")
                self.log("[step %d] 大脑给出最终答复，闭环结束。" % step)
                break

            # 记录 assistant 决策（OpenAI 协议形状，可供 LLM 大脑回放）
            # 注意：tool_call_id 必须全局唯一，否则同一批次内的 id 会跨步骤冲突
            call_specs = [("s%d_c%d" % (step, idx), c)
                          for idx, c in enumerate(decision.tool_calls)]
            messages.append({
                "role": "assistant",
                "content": decision.content or "",
                "tool_calls": [
                    {"id": cid, "type": "function",
                     "function": {"name": c.name,
                                  "arguments": json.dumps(c.arguments, ensure_ascii=False)}}
                    for cid, c in call_specs
                ],
            })
            self.log("")
            self.log("[step %d] 决策：调用 %d 个工具" % (step, len(call_specs)))

            for cid, c in call_specs:
                args_txt = json.dumps(c.arguments, ensure_ascii=False)
                self.log("   -> TOOL_CALL %s(%s)" % (c.name, args_txt[:120]))
                result = self.executor.execute(c)
                messages.append({
                    "role": "tool", "tool_call_id": cid, "name": c.name,
                    "content": json.dumps(result, ensure_ascii=False),
                })
                summary = summarize(c.name, result)
                self.log("   <- RESULT    %s | %s" % (c.name, summary))
                self._event("step%d" % step, "TOOL_CALL %s(%s) => %s" % (c.name, args_txt[:200], summary))
        else:
            final_content = "[Agent] 达到最大步数 %d，强制结束。" % self.max_steps

        self.log("")
        self.log("-" * 72)
        self.log(final_content)
        self.log("-" * 72)
        self._save_report(task, final_content)
        return final_content

    # ------------------------------------------------------------------ 辅助
    def _event(self, kind: str, text: str):
        self.events.append((datetime.now().strftime("%H:%M:%S"), kind, text))

    def _save_report(self, task: str, final_content: str):
        try:
            os.makedirs(self.report_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(self.report_dir, "sre_report_%s.md" % ts)
            lines = [
                "# SRE Agent 执行轨迹",
                "",
                "- 时间: %s" % datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "- 大脑: %s" % self.brain.name,
                "- 任务: %s" % task,
                "",
                "## 工具调用轨迹",
                "",
            ]
            for t, kind, text in self.events:
                if kind == "task":
                    continue
                lines.append("- [%s] %s" % (t, text))
            lines += ["", "## 最终报告", "", final_content, ""]
            with open(path, "w", encoding="utf-8") as f:
                f.write(chr(10).join(lines))
            self.log("报告已保存: " + path)
        except OSError as e:
            self.log("报告保存失败: %s" % e)
