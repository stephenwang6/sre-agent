"""运行时配置：全部支持环境变量覆盖（在 get_settings() 调用时读取）。"""
import os
from dataclasses import dataclass


@dataclass
class Settings:
    # ---- NetBox ----
    netbox_url: str = "http://192.168.247.61:8000"
    netbox_token: str = ""

    # ---- LLM（OpenAI 兼容协议）。api_key 为空时使用本地策略大脑 ----
    llm_base_url: str = "https://api.openai.com/v1"
    llm_api_key: str = ""
    llm_model: str = "gpt-4o-mini"

    # ---- Agent ----
    max_steps: int = 25
    request_timeout: int = 30


def get_settings() -> Settings:
    """在调用时读取环境变量（保证 .env 加载后再取生效）。"""
    return Settings(
        netbox_url=os.environ.get("NETBOX_URL", "http://192.168.247.61:8000"),
        netbox_token=os.environ.get("NETBOX_TOKEN", ""),
        llm_base_url=os.environ.get("SRE_LLM_BASE_URL", "https://api.openai.com/v1"),
        llm_api_key=os.environ.get("SRE_LLM_API_KEY", ""),
        llm_model=os.environ.get("SRE_LLM_MODEL", "gpt-4o-mini"),
        max_steps=int(os.environ.get("SRE_MAX_STEPS", "25")),
        request_timeout=int(os.environ.get("SRE_HTTP_TIMEOUT", "30")),
    )
