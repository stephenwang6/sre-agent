#!/usr/bin/env python3
"""AI-Native SRE Agent —— 命令行入口。

用法：
  python3 main.py seed                # 只注入演示拓扑与异常
  python3 main.py run                 # 只跑 Agent 闭环（假设已有数据）
  python3 main.py all                 # seed + run（完整演示）
  python3 main.py reset               # 清理演示数据
  python3 main.py all --approve-all   # 自动批准写操作（无人值守演示）
"""
from __future__ import annotations

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sre_agent.brain import LocalPolicyBrain, build_brain  # noqa: E402
from sre_agent.client import NetBoxClient  # noqa: E402
from sre_agent.config import get_settings  # noqa: E402
from sre_agent.runtime import AgentRuntime, ToolExecutor  # noqa: E402
from sre_agent.tools import ToolContext  # noqa: E402
from scenarios.seed_topology import reset, seed  # noqa: E402

TASK = (
    "对 NetBox 及其 Docker 承载环境执行一次完整巡检闭环："
    "1) 发现异常；2) 对每个异常取证诊断，给出根因；"
    "3) 基于证据执行最小影响的处置动作；4) 二次扫描复核；5) 输出中文汇总报告。"
    "安全要求：没有明确证据表明是陈旧数据时禁止删除；所有写操作需审批。"
)


def load_dotenv(path: str = ".env"):
    """极简 .env 加载（不覆盖已有环境变量）。"""
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            os.environ.setdefault(k.strip(), v.strip())


def make_approval(approve_all: bool):
    if approve_all:
        def cb(proposal):
            print("   [审批] 自动批准: %s %s" % (proposal["tool"], proposal["arguments"]))
            return True
        return cb

    def cb(proposal):
        print("   [审批请求] %s（安全等级: %s）" % (proposal["tool"], proposal["safety"]))
        print("     参数: %s" % proposal["arguments"])
        ans = input("     批准执行？[y/N] ")
        return ans.strip().lower() in ("y", "yes")
    return cb


def main():
    parser = argparse.ArgumentParser(description="AI-Native SRE Agent（NetBox Tool-Calling 闭环）")
    parser.add_argument("command", choices=["seed", "run", "reset", "all"], nargs="?", default="all")
    parser.add_argument("--approve-all", action="store_true", help="自动批准所有写操作")
    parser.add_argument("--brain", choices=["auto", "local", "llm"], default="auto",
                        help="auto: 有 LLM Key 用 LLM，否则用本地策略大脑")
    args = parser.parse_args()

    load_dotenv()
    settings = get_settings()
    nb = NetBoxClient(settings.netbox_url, settings.netbox_token, settings.request_timeout)

    if args.command in ("seed", "all"):
        print("### 注入演示拓扑与异常 ###")
        seed(nb)
        print("")
    if args.command == "reset":
        reset(nb)
        return
    if args.command in ("run", "all"):
        if args.brain == "local":
            brain = LocalPolicyBrain()
        else:
            brain = build_brain(settings)
        executor = ToolExecutor(ToolContext(netbox=nb), approval_callback=make_approval(args.approve_all))
        runtime = AgentRuntime(brain=brain, executor=executor, max_steps=settings.max_steps)
        runtime.run(TASK)


if __name__ == "__main__":
    main()
