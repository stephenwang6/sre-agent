"""场景种子：在 NetBox 中搭建演示拓扑，并注入三类真实感异常。

拓扑（站点 bj-a-dc，网段 10.20.30.0/24）：
  RACK-A01: core-sw-01(核心交换机, active) / dist-sw-02(汇聚, active) / old-server-05(服务器, decommissioning)
  RACK-A02: branch-ap-07(AP, planned) / app-srv-03(服务器, active)

注入异常：
  A1 前缀重叠      10.20.30.128/25 误建于业务网段 10.20.30.0/24 之内（同站点、无 IP 分配）
  A2 陈旧分配      old-server-05 已下线却仍持有活跃 IP 10.20.30.40，且 eth1 仍连接在网交换机（残留连线）
  A3 状态不一致    branch-ap-07 状态为 planned，但实际已布线（dist-sw-02:eth2）且持有活跃 IP 10.20.30.88
"""
from __future__ import annotations

import sys

sys.path.insert(0, "/data/AI-Native-SRE")

from sre_agent.client import NetBoxClient, NetBoxError  # noqa: E402

SITE_SLUG = "bj-a-dc"
SITE_NAME = "北京A数据中心"
PREFIX_CIDR = "10.20.30.0/24"
OVERLAP_CIDR = "10.20.30.128/25"
CONFLICT_IP = "10.20.30.40/24"


def get_or_create(nb: NetBoxClient, path: str, lookup: dict, payload: dict):
    existing = nb.get(path, lookup).get("results", [])
    if existing:
        return existing[0], False
    return nb.post(path, payload), True


def create_ip(nb: NetBoxClient, address: str, interface_id: int, description: str = ""):
    """按 (address, interface) 精确查找后创建，允许同一地址存在多条记录（用于制造冲突）。"""
    existing = nb.get("ipam/ip-addresses", {
        "address": address, "interface_id": interface_id,
    }).get("results", [])
    if existing:
        return existing[0], False
    payload = {
        "address": address,
        "status": "active",
        "assigned_object_type": "dcim.interface",
        "assigned_object_id": interface_id,
        "description": description,
    }
    return nb.post("ipam/ip-addresses", payload), True


def connect(nb: NetBoxClient, if_a: int, if_b: int, label: str):
    for c in nb.get_all("dcim/cables"):
        ids = set()
        for side in ("a_terminations", "b_terminations"):
            for t in c.get(side) or []:
                ids.add(t.get("object_id"))
        if ids == {if_a, if_b}:
            return c, False
    cable = nb.post("dcim/cables", {
        "a_terminations": [{"object_type": "dcim.interface", "object_id": if_a}],
        "b_terminations": [{"object_type": "dcim.interface", "object_id": if_b}],
        "status": "connected",
        "type": "cat6",
        "label": label,
    })
    return cable, True


def seed(nb: NetBoxClient) -> dict:
    log = []

    def note(msg):
        log.append(msg)
        print(msg, flush=True)

    # ---- 基础对象 ----
    site, c = get_or_create(nb, "dcim/sites/", {"slug": SITE_SLUG},
                            {"name": SITE_NAME, "slug": SITE_SLUG, "status": "active",
                             "description": "SRE Agent 演示站点"})
    note("site: %s (%s)" % (site["name"], "created" if c else "exists"))

    mfr, _ = get_or_create(nb, "dcim/manufacturers/", {"slug": "generic"},
                           {"name": "Generic", "slug": "generic"})
    roles = {}
    for name, slug, color in [("核心交换机", "core-switch", "2196f3"),
                              ("汇聚交换机", "dist-switch", "4caf50"),
                              ("服务器", "server", "ff9800"),
                              ("无线AP", "ap", "9c27b0")]:
        r, _ = get_or_create(nb, "dcim/device-roles/", {"slug": slug},
                             {"name": name, "slug": slug, "color": color})
        roles[slug] = r
    dtypes = {}
    for model, slug, uh in [("S6850-56HF", "s6850-56hf", 1),
                            ("RH2288H-V5", "rh2288h-v5", 2),
                            ("AP-1000", "ap-1000", 1)]:
        dt, _ = get_or_create(nb, "dcim/device-types/", {"slug": slug},
                              {"manufacturer": mfr["id"], "model": model, "slug": slug, "u_height": uh})
        dtypes[slug] = dt
    racks = {}
    for name in ("RACK-A01", "RACK-A02"):
        rk, _ = get_or_create(nb, "dcim/racks/", {"site_id": site["id"], "name": name},
                              {"name": name, "site": site["id"], "status": "active"})
        racks[name] = rk
    get_or_create(nb, "ipam/prefixes/", {"prefix": PREFIX_CIDR},
                  {"prefix": PREFIX_CIDR, "status": "active",
                   "scope_type": "dcim.site", "scope_id": site["id"],
                   "description": "业务网段"})
    # 注入 A1：与业务网段重叠的误建嵌套网段（同站点、无 IP 分配）
    get_or_create(nb, "ipam/prefixes/", {"prefix": OVERLAP_CIDR},
                  {"prefix": OVERLAP_CIDR, "status": "active",
                   "scope_type": "dcim.site", "scope_id": site["id"],
                   "description": "误建的嵌套网段（与业务网段重叠）"})
    note("基础对象就绪: 4 roles, 3 device-types, 2 racks, 2 prefixes")

    # ---- 设备 ----
    devices = {}
    specs = [
        ("core-sw-01", "s6850-56hf", "core-switch", "active", "RACK-A01", 10),
        ("dist-sw-02", "s6850-56hf", "dist-switch", "active", "RACK-A01", 20),
        ("old-server-05", "rh2288h-v5", "server", "decommissioning", "RACK-A01", 30),
        ("branch-ap-07", "ap-1000", "ap", "planned", "RACK-A02", 5),
        ("app-srv-03", "rh2288h-v5", "server", "active", "RACK-A02", 8),
    ]
    for name, dt, role, status, rack, pos in specs:
        dv, c = get_or_create(nb, "dcim/devices/", {"name": name, "site_id": site["id"]}, {
            "name": name, "site": site["id"], "device_type": dtypes[dt]["id"],
            "role": roles[role]["id"], "status": status,
            "rack": racks[rack]["id"], "position": pos, "face": "front",
            "serial": "SN-" + name.upper(),
        })
        devices[name] = dv
        note("device: %-14s status=%-14s (%s)" % (name, status, "created" if c else "exists"))

    # ---- 接口 ----
    def iface(dev_name, if_name):
        dev = devices[dev_name]
        ex = nb.get("dcim/interfaces/", {"device_id": dev["id"], "name": if_name}).get("results", [])
        if ex:
            return ex[0]
        return nb.post("dcim/interfaces/", {
            "device": dev["id"], "name": if_name, "type": "1000base-t", "enabled": True,
        })

    ifaces = {}
    for dev_name, names in [("core-sw-01", ["eth1", "eth2", "eth3"]),
                            ("dist-sw-02", ["eth1", "eth2", "eth3"]),
                            ("old-server-05", ["eth0", "eth1"]),
                            ("branch-ap-07", ["eth0"]),
                            ("app-srv-03", ["eth0"])]:
        for n in names:
            ifaces[(dev_name, n)] = iface(dev_name, n)
    note("interfaces: %d 个就绪" % len(ifaces))

    # ---- IP（含注入的陈旧分配）----
    ips = {}
    ip1, c1 = create_ip(nb, "10.20.30.1/24", ifaces[("core-sw-01", "eth1")]["id"],
                        "核心交换机管理地址")
    ips["core_mgmt"] = ip1
    ip2, c2 = create_ip(nb, CONFLICT_IP, ifaces[("old-server-05", "eth0")]["id"],
                        "历史遗留分配（设备已下线待回收）")
    ips["stale"] = ip2
    ip3, _ = create_ip(nb, "10.20.30.88/24", ifaces[("branch-ap-07", "eth0")]["id"], "AP 业务地址")
    ips["ap"] = ip3
    ip4, _ = create_ip(nb, "10.20.30.50/24", ifaces[("app-srv-03", "eth0")]["id"], "应用服务器地址")
    ips["app"] = ip4
    note("ip-addresses: 4 条（含下线设备陈旧分配 %s）" % CONFLICT_IP)

    # ---- 线缆 ----
    cables = {}
    cab, c = connect(nb, ifaces[("core-sw-01", "eth2")]["id"], ifaces[("dist-sw-02", "eth1")]["id"], "核心-汇聚上行")
    if cab:
        cables["uplink"] = cab
    cab, c = connect(nb, ifaces[("core-sw-01", "eth3")]["id"], ifaces[("old-server-05", "eth1")]["id"], "核心-旧服务器(下线残留)")
    if cab:
        cables["stale_link"] = cab
    cab, c = connect(nb, ifaces[("dist-sw-02", "eth2")]["id"], ifaces[("branch-ap-07", "eth0")]["id"], "汇聚-AP(已部署未登记)")
    if cab:
        cables["ap_link"] = cab
    cab, c = connect(nb, ifaces[("dist-sw-02", "eth3")]["id"], ifaces[("app-srv-03", "eth0")]["id"], "汇聚-应用服务器")
    if cab:
        cables["app_link"] = cab
    note("cables: %d 条就绪" % len(cables))

    # ---- 预置历史日志（给诊断阶段提供佐证）----
    jr = nb.get("extras/journal-entries", {
        "assigned_object_type": "dcim.device",
        "assigned_object_id": devices["old-server-05"]["id"],
    }).get("results", [])
    if not jr:
        nb.post("extras/journal-entries", {
            "assigned_object_type": "dcim.device",
            "assigned_object_id": devices["old-server-05"]["id"],
            "kind": "warning",
            "comments": "2026-10-01 设备已下电搬迁至备件库，10.20.30.0/24 中的地址应回收，请检查残留配置。",
        })
        note("journal: old-server-05 预置 1 条警告日志")

    note("")
    note(">>> 异常注入完成：")
    note("  A1 前缀重叠: %s 误建于 %s 之内（同站点，无 IP 分配）" % (OVERLAP_CIDR, PREFIX_CIDR))
    note("  A2 陈旧分配: old-server-05(decommissioning) 仍持有活跃 IP %s，且 eth1 仍连接在网交换机" % CONFLICT_IP)
    note("  A3 状态不一致: branch-ap-07(planned) 实际已布线且持有活跃 IP 10.20.30.88")
    return {"devices": devices, "ips": ips, "cables": cables}


def reset(nb: NetBoxClient):
    """删除演示数据（仅限本场景创建的对象，按依赖顺序清理）。"""
    sites = nb.get("dcim/sites/", {"slug": SITE_SLUG}).get("results", [])
    if not sites:
        print("无需重置：演示站点不存在")
        return
    site = sites[0]
    devices = nb.get("dcim/devices/", {"site_id": site["id"]}).get("results", [])
    for d in devices:
        nb.delete("dcim/devices/%d" % d["id"])
        print("deleted device", d["name"])
    for rk in nb.get("dcim/racks/", {"site_id": site["id"]}).get("results", []):
        nb.delete("dcim/racks/%d" % rk["id"])
    nb.delete("ipam/prefixes/%d" % nb.get("ipam/prefixes/", {"prefix": PREFIX_CIDR})["results"][0]["id"])         if nb.get("ipam/prefixes/", {"prefix": PREFIX_CIDR})["results"] else None
    nb.delete("dcim/sites/%d" % site["id"])
    print("reset done")
