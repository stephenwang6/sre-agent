"""工具层：OpenAI function-calling 兼容的工具注册表 + 实现。

三类工具：
  发现（read）  ：服务健康 / IP 冲突扫描 / 状态一致性扫描 / 容器状态
  诊断（read）  ：对象详情 / IP 分配查询 / 设备上下文（含日志）
  处置（write / dangerous）：更新对象 / 删除对象 / 写日志 / 重启容器

安全模型：每个工具有 safety 等级；read 直接执行，write/dangerous 必须经过
运行时审批回调（approval_callback）才允许执行。
"""
from __future__ import annotations

import ipaddress
import json
import shutil
import subprocess
from dataclasses import dataclass
from typing import Any, Callable

from .client import NetBoxError

READ = "read"
WRITE = "write"
DANGEROUS = "dangerous"

# 允许查询/操作的对象类型白名单（防止编造任意 path）及其真实 API 路径
OBJECT_PATHS = {
    "sites": "dcim/sites",
    "racks": "dcim/racks",
    "devices": "dcim/devices",
    "device-types": "dcim/device-types",
    "device-roles": "dcim/device-roles",
    "manufacturers": "dcim/manufacturers",
    "interfaces": "dcim/interfaces",
    "ip-addresses": "ipam/ip-addresses",
    "prefixes": "ipam/prefixes",
    "cables": "dcim/cables",
    "tenants": "tenancy/tenants",
}
OBJECT_TYPES = set(OBJECT_PATHS)
MUTABLE_TYPES = {"devices", "interfaces", "ip-addresses", "cables", "sites", "racks", "prefixes"}
DELETABLE_TYPES = {"ip-addresses", "interfaces", "cables", "prefixes"}
JOURNAL_TARGET_TYPES = {"dcim.device", "dcim.rack", "dcim.site", "ipam.ipaddress", "ipam.prefix"}

# 视为“非在网”的设备状态：其上的活跃 IP 分配属于陈旧数据
STALE_DEVICE_STATUSES = {"decommissioning", "decommissioned", "offline", "failed", "inventory", "staged"}
JOURNAL_KINDS = {"info", "success", "warning", "danger"}


@dataclass
class ToolContext:
    netbox: Any                      # NetBoxClient
    docker_prefix: str = "netbox-docker-"


@dataclass
class Tool:
    name: str
    description: str
    parameters: dict
    handler: Callable
    safety: str = READ


REGISTRY: dict[str, Tool] = {}


def register(name: str, description: str, parameters: dict, safety: str = READ):
    def deco(fn: Callable):
        REGISTRY[name] = Tool(name, description, parameters, fn, safety)
        return fn
    return deco


def get_tool(name: str):
    return REGISTRY.get(name)


def tool_schemas() -> list:
    """导出为 OpenAI function-calling 兼容的 tools 列表。"""
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            },
        }
        for t in REGISTRY.values()
    ]


# ---------------------------------------------------------------------------
# 小工具函数
# ---------------------------------------------------------------------------
def _status_value(obj: dict):
    st = obj.get("status")
    if isinstance(st, dict):
        return st.get("value")
    return st


def _display(obj):
    if isinstance(obj, dict):
        return obj.get("display") or obj.get("name")
    return obj if isinstance(obj, str) else None


def _device_of_assigned(ip: dict) -> dict:
    """IP 的 assigned_object（接口）中的设备摘要。"""
    ao = ip.get("assigned_object") or {}
    if not isinstance(ao, dict):
        return {}
    dev = ao.get("device") or {}
    return {
        "ip_id": ip.get("id"),
        "address": ip.get("address"),
        "ip_status": _status_value(ip),
        "description": ip.get("description"),
        "interface_id": ao.get("id"),
        "interface": ao.get("name") or ao.get("display"),
        "device_id": dev.get("id"),
        "device": dev.get("display") or dev.get("name"),
        "enabled": ao.get("enabled"),
    }


def _enrich_device_status(ctx: ToolContext, assignments: list) -> list:
    """为每个占用点补充其设备的当前状态（用于判断谁是陈旧分配）。"""
    cache = {}
    for a in assignments:
        did = a.get("device_id")
        if not did:
            a["device_status"] = None
            continue
        if did not in cache:
            try:
                dev = ctx.netbox.get("dcim/devices/%d" % did)
                cache[did] = _status_value(dev)
            except NetBoxError:
                cache[did] = None
        a["device_status"] = cache[did]
    return assignments


# ===========================================================================
# 一、发现类工具（read）
# ===========================================================================
@register(
    "netbox_service_health",
    "检查 NetBox 服务自身健康状态（/api/status/），返回版本信息与 RQ worker 运行情况。巡检第一步。",
    {"type": "object", "properties": {}, "additionalProperties": False},
)
def _t_service_health(args: dict, ctx: ToolContext) -> dict:
    st = ctx.netbox.get("status")
    return {
        "ok": True,
        "netbox_version": st.get("netbox-version"),
        "django_version": st.get("django_version") or st.get("django-version"),
        "python_version": st.get("python-version"),
        "rq_workers_running": st.get("rq-workers-running"),
    }


def _ip_in(address, net) -> bool:
    try:
        return ipaddress.ip_address((address or "").split("/")[0]) in net
    except ValueError:
        return False


@register(
    "netbox_scan_ip_conflicts",
    "IPAM 冲突扫描：a) 同一 IP 地址被重复分配；b) 同一站点/VRF 下相互重叠的前缀（嵌套网段冲突）。返回冲突明细。",
    {"type": "object", "properties": {}, "additionalProperties": False},
)
def _t_scan_ip_conflicts(args: dict, ctx: ToolContext) -> dict:
    prefixes = ctx.netbox.get_all("ipam/prefixes")
    ips = ctx.netbox.get_all("ipam/ip-addresses")
    anomalies = []

    # ---- 1) 重复 IP 分配（同一地址存在多个对象）----
    groups = {}
    for ip in ips:
        groups.setdefault(ip.get("address") or "?", []).append(ip)
    for addr, items in sorted(groups.items()):
        if len(items) < 2:
            continue
        assignments = _enrich_device_status(ctx, [_device_of_assigned(ip) for ip in items])
        anomalies.append({
            "anomaly": "ip_conflict",
            "address": addr,
            "count": len(items),
            "assignments": assignments,
        })

    # ---- 2) 同范围（站点/VRF）重叠前缀 ----
    def scope_key(p):
        vrf = p.get("vrf")
        vrf_id = vrf.get("id") if isinstance(vrf, dict) else vrf
        return (p.get("scope_type"), p.get("scope_id"), vrf_id)

    nets = {}
    for p in prefixes:
        try:
            net = ipaddress.ip_network(p.get("prefix") or "", strict=False)
        except ValueError:
            continue
        nets.setdefault(scope_key(p), []).append((net, p))

    for items in nets.values():
        for net_a, pa in items:
            for net_b, pb in items:
                if pa["id"] == pb["id"] or net_a.version != net_b.version:
                    continue
                if net_a.prefixlen > net_b.prefixlen and net_a.subnet_of(net_b):
                    inside = [
                        {"ip_id": ip.get("id"), "address": ip.get("address"),
                         "description": ip.get("description")}
                        for ip in ips if _ip_in(ip.get("address"), net_a)
                    ]
                    anomalies.append({
                        "anomaly": "overlapping_prefix",
                        "child": {"id": pa["id"], "prefix": pa["prefix"],
                                  "description": pa.get("description"), "status": _status_value(pa)},
                        "parent": {"id": pb["id"], "prefix": pb["prefix"],
                                   "description": pb.get("description")},
                        "ips_in_child": inside,
                    })

    return {
        "ok": True,
        "scanned_prefixes": len(prefixes),
        "scanned_ips": len(ips),
        "conflict_count": len(anomalies),
        "anomalies": anomalies,
    }


@register(
    "netbox_scan_status_consistency",
    "扫描设备状态一致性：a) planned(规划中) 设备却已布线/持有活跃 IP（实际已部署但状态未更新）；"
    "b) 已下线/故障设备上仍存在活跃 IP 分配（陈旧数据）。返回异常清单。",
    {"type": "object", "properties": {}, "additionalProperties": False},
)
def _t_scan_status_consistency(args: dict, ctx: ToolContext) -> dict:
    devices = ctx.netbox.get_all("dcim/devices")
    interfaces = ctx.netbox.get_all("dcim/interfaces")
    ips = ctx.netbox.get_all("ipam/ip-addresses")

    ifaces_by_device = {}
    for i in interfaces:
        did = (i.get("device") or {}).get("id")
        if did:
            ifaces_by_device.setdefault(did, []).append(i)

    ips_by_iface = {}
    for ip in ips:
        ao = ip.get("assigned_object") or {}
        if ip.get("assigned_object_type") == "dcim.interface" and isinstance(ao, dict):
            ips_by_iface.setdefault(ao.get("id"), []).append(ip)

    anomalies = []
    for d in devices:
        did = d.get("id")
        st = _status_value(d)
        ifaces = ifaces_by_device.get(did, [])
        my_ips = [ip for i in ifaces for ip in ips_by_iface.get(i.get("id"), [])]
        active_ips = [
            {"ip_id": ip.get("id"), "address": ip.get("address"),
             "interface": (ip.get("assigned_object") or {}).get("name")}
            for ip in my_ips if _status_value(ip) == "active"
        ]
        cabled_ifaces = [i.get("name") for i in ifaces
                         if i.get("cabled") or i.get("cable") or i.get("connected_endpoints")]

        if st == "planned" and (cabled_ifaces or active_ips):
            anomalies.append({
                "anomaly": "planned_but_deployed",
                "device_id": did,
                "device": d.get("name"),
                "device_status": st,
                "evidence": {
                    "cabled_interfaces": cabled_ifaces,
                    "active_ip_assignments": active_ips,
                    "rack": _display(d.get("rack")),
                },
            })
        elif st in STALE_DEVICE_STATUSES and active_ips:
            anomalies.append({
                "anomaly": "stale_assignments_on_inactive_device",
                "device_id": did,
                "device": d.get("name"),
                "device_status": st,
                "evidence": {"active_ip_assignments": active_ips},
            })

    return {
        "ok": True,
        "scanned_devices": len(devices),
        "anomaly_count": len(anomalies),
        "anomalies": anomalies,
    }


@register(
    "docker_container_status",
    "查看承载 NetBox 的 Docker 容器运行状态（netbox / worker / postgres / redis 等），用于基础设施层诊断。",
    {"type": "object", "properties": {}, "additionalProperties": False},
)
def _t_docker_status(args: dict, ctx: ToolContext) -> dict:
    if not shutil.which("docker"):
        return {"ok": False, "error": "docker CLI 不可用"}
    try:
        r = subprocess.run(
            ["docker", "ps", "--filter", "name=" + ctx.docker_prefix, "--format", "{{json .}}"],
            capture_output=True, text=True, timeout=20,
        )
    except Exception as e:
        return {"ok": False, "error": "docker ps 失败: %s" % e}
    if r.returncode != 0:
        return {"ok": False, "error": r.stderr.strip()[:300]}
    containers, unhealthy = [], []
    for line in r.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            j = json.loads(line)
        except ValueError:
            continue
        status = j.get("Status", "")
        if "(healthy)" in status:
            health = "healthy"
        elif status.startswith("Up"):
            health = "running"
        else:
            health = "unhealthy"
            unhealthy.append(j.get("Names"))
        containers.append({
            "name": j.get("Names"), "image": j.get("Image"),
            "status": status, "health": health, "ports": j.get("Ports", ""),
        })
    return {"ok": True, "containers": containers, "unhealthy": unhealthy}


# ===========================================================================
# 二、诊断类工具（read）
# ===========================================================================
@register(
    "netbox_get_object",
    "按类型和 ID 获取 NetBox 对象详情（sites/racks/devices/interfaces/ip-addresses/cables/prefixes 等）。",
    {
        "type": "object",
        "properties": {
            "object_type": {"type": "string", "enum": sorted(OBJECT_TYPES)},
            "id": {"type": "integer"},
        },
        "required": ["object_type", "id"],
        "additionalProperties": False,
    },
)
def _t_get_object(args: dict, ctx: ToolContext) -> dict:
    ot = args.get("object_type")
    oid = args.get("id")
    if ot not in OBJECT_TYPES or not isinstance(oid, int):
        return {"ok": False, "error": "非法 object_type 或 id"}
    obj = ctx.netbox.get("%s/%d" % (OBJECT_PATHS[ot], oid))
    return {"ok": True, "object": obj}


@register(
    "netbox_get_ip_assignments",
    "查询某个 IP 地址在 NetBox 中的全部占用点（哪些设备/接口持有它），并附设备状态。用于 IP 冲突的根因定位。",
    {
        "type": "object",
        "properties": {"address": {"type": "string", "description": "IP 地址，如 10.20.30.40"}},
        "required": ["address"],
        "additionalProperties": False,
    },
)
def _t_get_ip_assignments(args: dict, ctx: ToolContext) -> dict:
    addr = args.get("address", "")
    ips = ctx.netbox.get("ipam/ip-addresses", {"address": addr}).get("results", [])
    assignments = _enrich_device_status(ctx, [_device_of_assigned(ip) for ip in ips])
    return {"ok": True, "address": addr, "count": len(assignments), "assignments": assignments}


@register(
    "netbox_get_device_context",
    "获取设备完整上下文：设备属性、接口、IP 分配、关联线缆、历史日志。诊断异常根因的主力工具。",
    {
        "type": "object",
        "properties": {"device_id": {"type": "integer"}},
        "required": ["device_id"],
        "additionalProperties": False,
    },
)
def _t_get_device_context(args: dict, ctx: ToolContext) -> dict:
    did = args.get("device_id")
    if not isinstance(did, int):
        return {"ok": False, "error": "device_id 必须是整数"}
    device = ctx.netbox.get("dcim/devices/%d" % did)
    ifaces = ctx.netbox.get_all("dcim/interfaces", {"device_id": did})
    iface_ids = set(i["id"] for i in ifaces)
    all_ips = ctx.netbox.get_all("ipam/ip-addresses")
    my_ips = [
        ip for ip in all_ips
        if ip.get("assigned_object_type") == "dcim.interface"
        and (ip.get("assigned_object") or {}).get("id") in iface_ids
    ]
    cables = ctx.netbox.get_all("dcim/cables")
    my_cables = [
        {"id": c.get("id"), "status": _status_value(c), "label": c.get("label"),
         "a_terminations": c.get("a_terminations"), "b_terminations": c.get("b_terminations")}
        for c in cables
        if any(t.get("object_id") in iface_ids
               for t in (c.get("a_terminations") or []) + (c.get("b_terminations") or []))
    ]
    try:
        journal = ctx.netbox.get("extras/journal-entries", {
            "assigned_object_type": "dcim.device", "assigned_object_id": did, "limit": 0,
        }).get("results", [])
        journal = [{"kind": j.get("kind"), "comments": j.get("comments"), "created": j.get("created")}
                    for j in journal]
    except NetBoxError:
        journal = []
    return {
        "ok": True,
        "device": {"id": device.get("id"), "name": device.get("name"),
                   "status": _status_value(device), "site": _display(device.get("site")),
                   "rack": _display(device.get("rack")), "role": _display(device.get("role")),
                   "description": device.get("description")},
        "interfaces": [{"id": i.get("id"), "name": i.get("name"), "enabled": i.get("enabled"),
                        "cabled": bool(i.get("cabled") or i.get("cable") or i.get("connected_endpoints")),
                        "type": i.get("type")} for i in ifaces],
        "ip_addresses": my_ips,
        "cables": my_cables,
        "journal_entries": journal,
    }


# ===========================================================================
# 三、处置类工具（write / dangerous，需审批）
# ===========================================================================
@register(
    "netbox_update_object",
    "更新 NetBox 对象属性（PATCH）。例如把 planned 状态设备改为 active。写操作，需要审批。",
    {
        "type": "object",
        "properties": {
            "object_type": {"type": "string", "enum": sorted(MUTABLE_TYPES)},
            "id": {"type": "integer"},
            "data": {"type": "object", "description": "要修改的字段，例如 status=active"},
        },
        "required": ["object_type", "id", "data"],
        "additionalProperties": False,
    },
    safety=WRITE,
)
def _t_update_object(args: dict, ctx: ToolContext) -> dict:
    ot, oid, data = args.get("object_type"), args.get("id"), args.get("data")
    if ot not in MUTABLE_TYPES or not isinstance(oid, int) or not isinstance(data, dict) or not data:
        return {"ok": False, "error": "参数非法：object_type/id/data"}
    obj = ctx.netbox.patch("%s/%d" % (OBJECT_PATHS[ot], oid), data)
    return {"ok": True, "action": "update", "object_type": ot, "id": oid,
            "changes": data, "result": {"id": obj.get("id"), "display": obj.get("display"),
                                        "status": _status_value(obj)}}


@register(
    "netbox_delete_object",
    "删除 NetBox 对象（DELETE）。例如删除冲突中的陈旧 IP 分配记录。危险操作，必须审批，且仅限 ip-addresses/interfaces/cables。",
    {
        "type": "object",
        "properties": {
            "object_type": {"type": "string", "enum": sorted(DELETABLE_TYPES)},
            "id": {"type": "integer"},
        },
        "required": ["object_type", "id"],
        "additionalProperties": False,
    },
    safety=DANGEROUS,
)
def _t_delete_object(args: dict, ctx: ToolContext) -> dict:
    ot, oid = args.get("object_type"), args.get("id")
    if ot not in DELETABLE_TYPES or not isinstance(oid, int):
        return {"ok": False, "error": "参数非法：仅允许删除 " + ", ".join(sorted(DELETABLE_TYPES))}
    ctx.netbox.delete("%s/%d" % (OBJECT_PATHS[ot], oid))
    return {"ok": True, "action": "delete", "object_type": ot, "id": oid}


@register(
    "netbox_add_journal_entry",
    "在 NetBox 对象上写日志（journal entry），记录处置过程，形成审计闭环。写操作，需要审批。",
    {
        "type": "object",
        "properties": {
            "assigned_object_type": {"type": "string", "enum": sorted(JOURNAL_TARGET_TYPES)},
            "assigned_object_id": {"type": "integer"},
            "kind": {"type": "string", "enum": sorted(JOURNAL_KINDS)},
            "comments": {"type": "string"},
        },
        "required": ["assigned_object_type", "assigned_object_id", "comments"],
        "additionalProperties": False,
    },
    safety=WRITE,
)
def _t_add_journal_entry(args: dict, ctx: ToolContext) -> dict:
    ot, oid = args.get("assigned_object_type"), args.get("assigned_object_id")
    comments = (args.get("comments") or "").strip()
    kind = args.get("kind") or "info"
    if ot not in JOURNAL_TARGET_TYPES or not isinstance(oid, int) or not comments:
        return {"ok": False, "error": "参数非法：assigned_object_type/assigned_object_id/comments 必填"}
    if kind not in JOURNAL_KINDS:
        return {"ok": False, "error": "kind 必须是 " + ", ".join(sorted(JOURNAL_KINDS))}
    entry = ctx.netbox.post("extras/journal-entries", {
        "assigned_object_type": ot, "assigned_object_id": oid,
        "kind": kind, "comments": comments,
    })
    return {"ok": True, "action": "journal", "entry_id": entry.get("id"), "kind": kind}


@register(
    "docker_restart_container",
    "重启承载 NetBox 的 Docker 容器（仅限 netbox-docker- 前缀）。危险操作，必须审批；默认场景不会自动调用。",
    {
        "type": "object",
        "properties": {"container_name": {"type": "string", "description": "如 netbox-docker-netbox-1"}},
        "required": ["container_name"],
        "additionalProperties": False,
    },
    safety=DANGEROUS,
)
def _t_restart_container(args: dict, ctx: ToolContext) -> dict:
    name = args.get("container_name") or ""
    if not name.startswith(ctx.docker_prefix):
        return {"ok": False, "error": "仅允许操作 " + ctx.docker_prefix + "* 容器"}
    if not shutil.which("docker"):
        return {"ok": False, "error": "docker CLI 不可用"}
    r = subprocess.run(["docker", "restart", name], capture_output=True, text=True, timeout=60)
    return {"ok": r.returncode == 0, "container": name,
            "output": (r.stdout + r.stderr).strip()[:300]}
