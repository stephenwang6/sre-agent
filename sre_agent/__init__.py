"""AI-Native SRE Agent — a tool-calling agent for NetBox operations.

闭环能力：发现异常 -> 诊断 -> 处置 -> 复核验证。
工具调用协议与 OpenAI function calling 兼容；大脑(brain)可插拔：
  - 本地策略大脑（默认，无需外部 LLM）
  - 任意 OpenAI 兼容 LLM（设置 SRE_LLM_BASE_URL / SRE_LLM_API_KEY 后自动切换）
"""

__version__ = "1.0.0"
