"""大脑层：把"观察 -> 决策"变成标准 tool_calls。

两个实现，输出同一协议：
  - LocalPolicyBrain        内置 SRE 巡检 Runbook 策略（默认，离线可用）
  - OpenAICompatibleBrain   任意 OpenAI 兼容 LLM（function calling）

决策协议：
  BrainDecision(tool_calls=[ToolCall(id, name, arguments), ...])  -> 继续执行工具
  BrainDecision(content="...")                                   -> 任务结束，输出最终答复
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field

from .tools import STALE_DEVICE_STATUSES


@dataclass
class ToolCall:
    id: str
    name: str
    arguments: dict


@dataclass
class BrainDecision:
    tool_calls: list = field(default_factory=list)
    content: str = ""


def _dumps(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, sort_keys=True)


def parse_messages(messages: list):
    """从 OpenAI 形状的消息历史中提取 (调用, 结果)。

    返回 executed: [(call_id, name, args, result_or_None), ...]
    """
    calls, results = {}, {}
    for m in messages:
        role = m.get("role")
        if role == "assistant":
            for tc in m.get("tool_calls") or []:
                fn = tc.get("function") or {}
                try:
                    args = json.loads(fn.get("arguments") or "{}")
                except ValueError:
                    args = {}
                calls[tc.get("id")] = (fn.get("name"), args)
        elif role == "tool":
            try:
                results[m.get("tool_call_id")] = json.loads(m.get("content") or "{}")
            except ValueError:
                results[m.get("tool_call_id")] = {"ok": False, "error": "结果无法解析"}
    executed = []
    for cid, (name, args) in calls.items():
        executed.append((cid, name, args, results.get(cid)))
    return executed


def _latest(executed, name):
    """某个工具最后一次成功执行的结果。"""
    out = None
    for cid, n, args, result in executed:
        if n == name and result is not None:
            out = result
    return out


def _count(executed, name):
    return sum(1 for cid, n, a, r in executed if n == name)


def _done(executed, name, args):
    """该 (工具, 参数) 是否已经调用过（无论成败，避免重复尝试）。"""
    key = _dumps(args)
    return any(n == name and _dumps(a) == key for cid, n, a, r in executed)


# ===========================================================================
# 本地策略大脑：一个确定性的 SRE Runbook，但每一步都是真实的 tool_calling
# ===========================================================================
class LocalPolicyBrain:
    """SRE 值班策略大脑。

    决策完全基于对消息历史中工具结果的观察（而非硬编码对象 ID）：
      阶段0 并行巡检   -> 阶段1 逐个异常取证诊断 -> 阶段2 按证据处置
      -> 阶段3 写审计日志 -> 阶段4 二次扫描复核 -> 阶段5 汇总报告
    """

    name = "local-policy"

    # ------------------------------------------------------------------ 入口
    def decide(self, messages: list, tools: list) -> BrainDecision:
        executed = parse_messages(messages)

        # ---- 阶段0：初始并行巡检 ----
        if _count(executed, "netbox_scan_ip_conflicts") == 0:
            return BrainDecision(tool_calls=self._batch([
                ("netbox_service_health", {}),
                ("netbox_scan_ip_conflicts", {}),
                ("netbox_scan_status_consistency", {}),
                ("docker_container_status", {}),
            ]))

        conflict_scan = _latest(executed, "netbox_scan_ip_conflicts") or {}
        consistency_scan = _latest(executed, "netbox_scan_status_consistency") or {}
        anomalies = (conflict_scan.get("anomalies") or []) + (consistency_scan.get("anomalies") or [])

        # ---- 阶段1：逐个异常取证诊断 ----
        diag = self._plan_diagnosis(anomalies, executed)
        if diag:
            return BrainDecision(tool_calls=self._batch(diag))

        # ---- 阶段2：按证据处置 ----
        remediation = self._plan_remediation(anomalies, executed)
        pending = [c for c in remediation if not _done(executed, c[0], c[1])]
        if pending:
            return BrainDecision(tool_calls=self._batch(pending))

        # ---- 阶段3：审计日志 ----
        journal = [c for c in self._plan_journal(executed) if not _done(executed, c[0], c[1])]
        if journal:
            return BrainDecision(tool_calls=self._batch(journal))

        # ---- 阶段4：复核（仅当发生过处置时） ----
        acted = any(r and r.get("action") in ("update", "delete") for c, n, a, r in executed)
        if anomalies and acted and _count(executed, "netbox_scan_ip_conflicts") < 2:
            return BrainDecision(tool_calls=self._batch([
                ("netbox_scan_ip_conflicts", {}),
                ("netbox_scan_status_consistency", {}),
            ]))

        # ---- 阶段5：汇总 ----
        return BrainDecision(content=self._final_report(executed, anomalies))

    # ------------------------------------------------------------------ 工具
    @staticmethod
    def _batch(pairs):
        return [ToolCall(id="call_%d" % i, name=n, arguments=a)
                for i, (n, a) in enumerate(pairs)]

    def _plan_diagnosis(self, anomalies, executed):
        """对每个异常的相关设备做完整上下文取证。"""
        plans, seen = [], set()
        for an in anomalies:
            kind = an.get("anomaly")
            if kind == "ip_conflict":
                dev_ids = [a.get("device_id") for a in an.get("assignments", []) if a.get("device_id")]
                addr = an.get("address")
                if addr and not _done(executed, "netbox_get_ip_assignments", {"address": addr}):
                    plans.append(("netbox_get_ip_assignments", {"address": addr}))
            elif kind == "overlapping_prefix":
                for obj in (an.get("child"), an.get("parent")):
                    if obj and not _done(executed, "netbox_get_object",
                                         {"object_type": "prefixes", "id": obj["id"]}):
                        plans.append(("netbox_get_object", {"object_type": "prefixes", "id": obj["id"]}))
                continue
            else:
                dev_ids = [an.get("device_id")]
            for did in dev_ids:
                if did and did not in seen and not _done(executed, "netbox_get_device_context", {"device_id": did}):
                    seen.add(did)
                    plans.append(("netbox_get_device_context", {"device_id": did}))
        return plans

    # -------------------------------------------------------------- 处置规划
    def _plan_remediation(self, anomalies, executed):
        """根据诊断证据生成处置计划（最小影响原则）。"""
        plans = []
        contexts = self._device_contexts(executed)

        for an in anomalies:
            kind = an.get("anomaly")

            if kind == "ip_conflict":
                assignments = an.get("assignments", [])
                stale = [a for a in assignments if a.get("device_status") in STALE_DEVICE_STATUSES]
                live = [a for a in assignments if a.get("device_status") not in STALE_DEVICE_STATUSES]
                # 只有在能明确区分"在网占用点"和"陈旧占用点"时才自动删除，否则留给人
                if stale and live:
                    for a in stale:
                        plans.append(("netbox_delete_object",
                                      {"object_type": "ip-addresses", "id": a["ip_id"]}))

            elif kind == "stale_assignments_on_inactive_device":
                did = an.get("device_id")
                for ip in an.get("evidence", {}).get("active_ip_assignments", []):
                    plans.append(("netbox_delete_object",
                                  {"object_type": "ip-addresses", "id": ip["ip_id"]}))
                # 该下线设备上残留的连线也一并清理（证据来自诊断上下文）
                for cable in (contexts.get(did) or {}).get("cables", []):
                    plans.append(("netbox_delete_object",
                                  {"object_type": "cables", "id": cable["id"]}))

            elif kind == "planned_but_deployed":
                plans.append(("netbox_update_object",
                              {"object_type": "devices", "id": an["device_id"],
                               "data": {"status": "active"}}))

            elif kind == "overlapping_prefix":
                # 子网段内无任何 IP 分配时才自动删除，否则留给人研判
                if not an.get("ips_in_child"):
                    plans.append(("netbox_delete_object",
                                  {"object_type": "prefixes", "id": an["child"]["id"]}))

        # 去重（同一 IP 可能同时被冲突处置和一致性处置覆盖）
        uniq, seen = [], set()
        for name, args in plans:
            key = (name, _dumps(args))
            if key not in seen:
                seen.add(key)
                uniq.append((name, args))
        return uniq

    def _plan_journal(self, executed):
        """为已成功执行的处置动作补写审计日志。"""
        plans = []
        contexts = self._device_contexts(executed)
        ip_owner = {}        # ip_id -> (device_id, device_name, address)
        prefix_parent = {}   # 被删子网段 -> 父网段 id（日志写到幸存对象上）
        for cid, name, args, result in executed:
            if name != "netbox_scan_ip_conflicts" or not result:
                continue
            for an in result.get("anomalies", []):
                for a in an.get("assignments", []):
                    ip_owner[a["ip_id"]] = (a.get("device_id"), a.get("device"), an.get("address"))
                if an.get("anomaly") == "overlapping_prefix":
                    prefix_parent[an["child"]["id"]] = an["parent"]["id"]

        for cid, name, args, result in executed:
            if not (result and result.get("ok")):
                continue
            if name == "netbox_delete_object" and args.get("object_type") == "ip-addresses":
                ipid = args.get("id")
                did, dname, addr = ip_owner.get(ipid, (None, "未知设备", "未知地址"))
                plans.append(("netbox_add_journal_entry", {
                    "assigned_object_type": "dcim.device", "assigned_object_id": did,
                    "kind": "warning",
                    "comments": "[SRE-Agent] 删除陈旧 IP 分配 %s（原属设备 %s，与在线设备冲突，已回收）。"
                                % (addr, dname),
                }))
            elif name == "netbox_update_object" and args.get("object_type") == "devices":
                disp = (result.get("result") or {}).get("display") or ("设备#%s" % args.get("id"))
                plans.append(("netbox_add_journal_entry", {
                    "assigned_object_type": "dcim.device", "assigned_object_id": args.get("id"),
                    "kind": "success",
                    "comments": "[SRE-Agent] 状态由 planned 修正为 active：设备已布线且持有活跃 IP，实际已部署。",
                }))
            elif name == "netbox_delete_object" and args.get("object_type") == "prefixes":
                # 已删除的对象无法挂日志，写到幸存的父网段上形成审计闭环
                parent_id = prefix_parent.get(args.get("id"))
                if parent_id:
                    plans.append(("netbox_add_journal_entry", {
                        "assigned_object_type": "ipam.prefix",
                        "assigned_object_id": parent_id,
                        "kind": "warning",
                        "comments": "[SRE-Agent] 已删除与本报段重叠且段内无 IP 分配的误建子网段（原 ID #%s）。"
                                    % args.get("id"),
                    }))
            elif name == "netbox_delete_object" and args.get("object_type") == "cables":
                cid2 = args.get("id")
                for did, ctx in contexts.items():
                    if any(c.get("id") == cid2 for c in (ctx or {}).get("cables", [])):
                        dname = (ctx.get("device") or {}).get("name")
                        plans.append(("netbox_add_journal_entry", {
                            "assigned_object_type": "dcim.device", "assigned_object_id": did,
                            "kind": "info",
                            "comments": "[SRE-Agent] 清理下线设备 %s 的残留连线 cable#%s。" % (dname, cid2),
                        }))
                        break
        return [p for p in plans if p[1].get("assigned_object_id")]

    @staticmethod
    def _device_contexts(executed):
        out = {}
        for cid, name, args, result in executed:
            if name == "netbox_get_device_context" and result:
                out[args.get("device_id")] = result
        return out

    # -------------------------------------------------------------- 汇总报告
    def _final_report(self, executed, anomalies) -> str:
        def first(name):
            for cid, n, a, r in executed:
                if n == name and r:
                    return r
            return {}

        health = first("netbox_service_health")
        docker = first("docker_container_status")
        disc_conflict = first("netbox_scan_ip_conflicts")
        disc_consistency = first("netbox_scan_status_consistency")
        disc_anoms = (disc_conflict.get("anomalies") or []) + (disc_consistency.get("anomalies") or [])
        verify_conflict = _latest(executed, "netbox_scan_ip_conflicts") or {}
        verify_consistency = _latest(executed, "netbox_scan_status_consistency") or {}
        contexts = self._device_contexts(executed)

        lines = []
        lines.append("# SRE 巡检闭环报告")
        lines.append("")
        lines.append("- NetBox: v%s（RQ workers: %s）" % (
            health.get("netbox_version"), health.get("rq_workers_running")))
        if docker.get("containers"):
            lines.append("- 容器: %d 个运行中，异常 %d 个" % (
                len(docker["containers"]), len(docker.get("unhealthy") or [])))
        lines.append("- 发现异常: %d 项" % len(disc_anoms))

        # 一、发现
        lines.append("")
        lines.append("## 一、发现异常")
        if not disc_anoms:
            lines.append("")
            lines.append("巡检未发现异常，系统状态正常。")
        for i, an in enumerate(disc_anoms, 1):
            lines.append("")
            if an["anomaly"] == "ip_conflict":
                lines.append("%d. **IP 冲突** `%s`：%d 个占用点" % (i, an["address"], an["count"]))
                for a in an.get("assignments", []):
                    lines.append("   - `%s` @ %s:%s（设备状态: %s）" % (
                        a.get("address"), a.get("device"), a.get("interface"), a.get("device_status")))
            elif an["anomaly"] == "stale_assignments_on_inactive_device":
                lines.append("%d. **陈旧分配**：设备 `%s`（状态 %s）上仍有活跃 IP" % (
                    i, an.get("device"), an.get("device_status")))
                for ip in an.get("evidence", {}).get("active_ip_assignments", []):
                    lines.append("   - %s @ %s" % (ip.get("address"), ip.get("interface")))
            elif an["anomaly"] == "overlapping_prefix":
                lines.append("%d. **前缀重叠**: `%s` 完全包含于 `%s`（同站点），子网段内 IP 分配 %d 个" % (
                    i, an["child"]["prefix"], an["parent"]["prefix"],
                    len(an.get("ips_in_child") or [])))
            else:
                ev = an.get("evidence", {})
                lines.append("%d. **状态不一致（planned 但已部署）**：设备 `%s`" % (i, an.get("device")))
                if ev.get("cabled_interfaces"):
                    lines.append("   - 已连接线缆的接口: %s" % ", ".join(ev["cabled_interfaces"]))
                for ip in ev.get("active_ip_assignments", []):
                    lines.append("   - 活跃 IP: %s @ %s" % (ip.get("address"), ip.get("interface")))

        # 二、诊断
        lines.append("")
        lines.append("## 二、诊断结论")
        if disc_anoms:
            for an in disc_anoms:
                if an["anomaly"] == "ip_conflict":
                    stale = [a for a in an.get("assignments", []) if a.get("device_status") in STALE_DEVICE_STATUSES]
                    live = [a for a in an.get("assignments", []) if a.get("device_status") not in STALE_DEVICE_STATUSES]
                    if stale and live:
                        lines.append("- `%s` 根因：已下线/故障设备 `%s` 上的陈旧 IP 记录未回收，"
                                     "与在网设备 `%s` 的地址冲突。" % (
                                         an["address"], stale[0].get("device"), live[0].get("device")))
                        ctx = contexts.get(stale[0].get("device_id")) or {}
                        jr = ctx.get("journal_entries") or []
                        if jr:
                            lines.append("  - 历史日志佐证：%s" % jr[0].get("comments"))
                    else:
                        lines.append("- `%s` 无法自动判定陈旧方（占用点均在网或信息不足），转人工研判。" % an["address"])
                elif an["anomaly"] == "stale_assignments_on_inactive_device":
                    lines.append("- 设备 `%s`（%s）残留活跃 IP 分配，属于应回收的陈旧数据。" % (
                        an.get("device"), an.get("device_status")))
                elif an["anomaly"] == "overlapping_prefix":
                    if an.get("ips_in_child"):
                        lines.append("- `%s` 与 `%s` 重叠且段内已有 IP 分配，需人工研判是否合并网段。" % (
                            an["child"]["prefix"], an["parent"]["prefix"]))
                    else:
                        lines.append("- `%s` 与 `%s` 重叠，段内无任何 IP 分配，属于误建的嵌套网段，应删除。" % (
                            an["child"]["prefix"], an["parent"]["prefix"]))
                else:
                    lines.append("- 设备 `%s` 状态为 planned，但实际已布线并持有活跃 IP，"
                                 "是部署后状态未更新的记录不一致。" % an.get("device"))
        else:
            lines.append("无需诊断。")

        # 三、处置
        lines.append("")
        lines.append("## 三、处置动作")
        actions = [(n, a, r) for c, n, a, r in executed
                   if n in ("netbox_update_object", "netbox_delete_object", "netbox_add_journal_entry")]
        if not actions:
            lines.append("无需处置。")
        for n, a, r in actions:
            status = "成功" if (r or {}).get("ok") else ("未获批准" if (r or {}).get("rejected") else "失败")
            if n == "netbox_delete_object":
                lines.append("- [删除] %s#%s -> %s" % (a.get("object_type"), a.get("id"), status))
            elif n == "netbox_update_object":
                lines.append("- [更新] %s#%s %s -> %s" % (
                    a.get("object_type"), a.get("id"), a.get("data"), status))
            else:
                lines.append("- [日志] %s#%s -> %s" % (
                    a.get("assigned_object_type"), a.get("assigned_object_id"), status))

        # 四、复核
        lines.append("")
        lines.append("## 四、复核验证")
        if actions:
            left = (verify_conflict.get("conflict_count") or 0) + (verify_consistency.get("anomaly_count") or 0)
            if verify_conflict or verify_consistency:
                lines.append("二次扫描：IP 冲突 %s 项，状态不一致 %s 项 -> %s" % (
                    verify_conflict.get("conflict_count"), verify_consistency.get("anomaly_count"),
                    "通过" if left == 0 else "未通过，仍有残留"))
            else:
                lines.append("未执行复核扫描。")
        else:
            lines.append("无处置动作，无需复核。")

        # 五、遗留
        lines.append("")
        lines.append("## 五、遗留与建议")
        rejected = [(n, a) for c, n, a, r in executed if (r or {}).get("rejected")]
        for n, a in rejected:
            lines.append("- 操作未获批准，需人工跟进：%s %s" % (n, a))
        unresolved = []
        for an in disc_anoms:
            if an["anomaly"] == "ip_conflict":
                stale = [x for x in an.get("assignments", []) if x.get("device_status") in STALE_DEVICE_STATUSES]
                live = [x for x in an.get("assignments", []) if x.get("device_status") not in STALE_DEVICE_STATUSES]
                if not (stale and live):
                    unresolved.append("IP 冲突 `%s` 需人工研判" % an["address"])
        for u in unresolved:
            lines.append("- " + u)
        if not rejected and not unresolved:
            lines.append("- 无遗留事项。建议将该巡检纳入定时任务（每日一次）。")
        lines.append("")
        lines.append("---")
        lines.append("本报告由 AI-Native SRE Agent 自动生成。")
        return chr(10).join(lines)


# ===========================================================================
# LLM 大脑：任意 OpenAI 兼容 API（v1/chat/completions + tools）
# ===========================================================================
LLM_SYSTEM_PROMPT = """你是一名 AI-Native SRE 值班工程师，通过工具调用（function calling）运维 NetBox 及其 Docker 承载环境。

工作流程（严格遵守）：
1. 发现异常：并行调用 netbox_service_health、netbox_scan_ip_conflicts、netbox_scan_status_consistency、docker_container_status 完成巡检。
2. 诊断：对每个异常，用 netbox_get_device_context / netbox_get_ip_assignments / netbox_get_object 取证，给出根因。
3. 处置：按最小影响原则提出写操作（netbox_update_object / netbox_delete_object / netbox_add_journal_entry）。写操作会提交人工审批，不要重复尝试被拒绝的操作。
4. 复核：处置后重新执行两个扫描工具，确认异常清零。
5. 汇总：输出中文 Markdown 报告（发现 / 诊断 / 处置 / 复核 / 遗留）。

安全红线：
- 没有明确证据表明某个 IP 分配是陈旧数据时，禁止删除。
- 禁止重启容器，除非服务健康检查失败且已说明理由。
- 每个异常都要先诊断再处置；不得跳过诊断直接删除。
- 优先使用影响最小的动作（更新状态优先于删除）。"""


class OpenAICompatibleBrain:
    """OpenAI 兼容 LLM 大脑（DeepSeek / Qwen / Moonshot / OpenAI 等均可）。"""

    name = "llm"

    def __init__(self, base_url: str, api_key: str, model: str, timeout: int = 120):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.timeout = timeout

    def decide(self, messages: list, tools: list) -> BrainDecision:
        import requests  # 延迟导入，本地策略模式无依赖

        payload = {
            "model": self.model,
            "messages": messages,
            "tools": tools,
            "tool_choice": "auto",
            "temperature": 0.2,
        }
        resp = requests.post(
            self.base_url + "/chat/completions",
            json=payload,
            headers={"Authorization": "Bearer " + self.api_key,
                     "Content-Type": "application/json"},
            timeout=self.timeout,
        )
        if resp.status_code >= 400:
            raise RuntimeError("LLM API 错误 %s: %s" % (resp.status_code, resp.text[:300]))
        msg = resp.json()["choices"][0]["message"]
        tool_calls = []
        for i, tc in enumerate(msg.get("tool_calls") or []):
            fn = tc.get("function") or {}
            try:
                args = json.loads(fn.get("arguments") or "{}")
            except ValueError:
                args = {}
            tool_calls.append(ToolCall(
                id=tc.get("id") or ("llm_call_%d" % i),
                name=fn.get("name") or "",
                arguments=args,
            ))
        if tool_calls:
            return BrainDecision(tool_calls=tool_calls, content=msg.get("content") or "")
        return BrainDecision(content=msg.get("content") or "")


def build_brain(settings):
    """按配置选择大脑：有 LLM Key 用 LLM，否则用本地策略大脑。"""
    if settings.llm_api_key:
        return OpenAICompatibleBrain(settings.llm_base_url, settings.llm_api_key, settings.llm_model)
    return LocalPolicyBrain()
